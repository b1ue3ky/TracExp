import os
import re

from tracexp.prompt import (CALL_IDENTITY_EXAMPLES, reflection_sys_prompt,
                        reflection_user_prompt, semantic_user_prompt,
                        syntax_sys_prompt, syntax_user_prompt)
from tracexp.utils import (TraceParser, decode_abi, extract_code_from_content,
                       flatten_call_trace, foundry_test_error, get_call_info,
                       get_func_name, locate_param_diff_flatten_line,
                       make_prompt, make_request, prettify_call_line,
                       read_code_from_file, read_errors,
                       read_evm_version_from_code_file, read_json, rm_file,
                       run_cmd, set_os_proxy, to_checksum_address,
                       try_import_value, write_code_to_file, CACHE_DIR, calltrace_diff)

def is_semantic_error_free(code_path, max_tries=3, forge_tries=3):
    for i in range(forge_tries):
        root_path = f"{CACHE_DIR}/result"
        stderr_path = f"{code_path.replace('.sol', '.test.stdeer')}"
        stdout_path = f"{code_path.replace('.sol', '.test.stdout')}"        
        forge_cmd = ["forge", "test", "--root", root_path, "--contracts", os.path.relpath(code_path, root_path), "-vvvv", "--color", "always"]
        evm_version = read_evm_version_from_code_file(code_path)
        if evm_version != "default":
            forge_cmd += ["--evm-version", evm_version]

        for j in range(max_tries):
            run_cmd(forge_cmd, stdout=stdout_path, stderr=stderr_path)
            errors = read_errors(stderr_path) # foundry test may errors, 
            if foundry_test_error(stdout_path) is not None:
                continue

            if len(errors) == 0: break
            
            if "--via-ir" in errors:
                run_cmd(forge_cmd + ["--via-ir"], stdout=stdout_path, stderr=stderr_path)
                errors = read_errors(stderr_path) # foundry test may errors, 
                
                if len(errors) == 0: 
                    forge_cmd = forge_cmd + ["--via-ir"]
                    break

        if (error:=foundry_test_error(stdout_path)) is not None:
            return forge_cmd, False, "setup failed: " + error
        
        parser = TraceParser()
        results = parser.parse_foundry_output(stdout_path)

        if len(results) > 0 and foundry_test_error(stdout_path) is None:
            break
        
        if len(results) == 0:
            return forge_cmd, False, "setup failed: no test results found in the log file."

    assert len(results) > 0, "No results found in the log file."
    
    if len(results) > 1:
        testPoc_result = [r for r in results if r.test_func and "testpoc" in r.test_func.lower()]
        if len(testPoc_result) == 0:
            testPoc_result = [r for r in results if r.test_func and "test" in r.test_func.lower()]
        
        assert len(testPoc_result) > 0, "No testPoc() result found in the log file."
        result = testPoc_result[0]
    else:
        result = results[0]
    
    if result.attack_successful:
        return forge_cmd, True, ""
    else:
        return forge_cmd, False, result
        # if make_diff:
        #     return False, calltrace_diff(result, ref_callgraph)
        # else:
        #     assert False, f"attack failed without semantic refinement {stdout_path}"
        #     return False, f"attack failed without semantic refinement {stdout_path}"

def refine_self_reflection(llm_client, code_path, user_prompt, max_iters=3, prefix="reflection_"):
    """
    Perform self-reflection on the generated code by comparing it with the original user prompt.
    This step happens after syntax refinement and before semantic refinement.

    Args:
        llm_client: LLM client to use
        code_path: Path to the syntax-refined code
        user_prompt: Original user prompt containing execution traces
        max_iters: Maximum iterations for self-reflection (default: 2)
        prefix: Prefix for output files

    Returns:
        dict with keys: code_path, iterations, histories, responses, success, avg_prompt_tokens, avg_completion_tokens
    """
    # global reflection_sys_prompt, reflection_user_prompt

    reflection_histories = []
    responses = []
    reflection_prompt_tokens = 0
    reflection_completion_tokens = 0

    print(f"Starting self-reflection phase...")

    for i in range(max_iters):
        # Read current code
        code = read_code_from_file(code_path)

        # Build self-reflection prompt
        user_prompt = reflection_user_prompt.format(
            user_prompt=user_prompt,
            code=code
        )
        sys_prompt = reflection_sys_prompt.format(examples=CALL_IDENTITY_EXAMPLES)
        prompt = make_prompt(llm_client, sys_prompt=sys_prompt, user_prompt=user_prompt)

        # Request LLM for self-reflection
        print(f"Self-reflection iteration {i+1}/{max_iters}...")
        response, reflection_history = make_request(llm_client, prompt)

        if not response:
            print(f"Self-reflection failed: network error")
            return {
                "code_path": code_path,
                "iterations": i,
                "histories": reflection_histories,
                "responses": responses,
                "success": False,
                "reflection_times": i,
                "avg_prompt_tokens": 0 if i == 0 else reflection_prompt_tokens / i,
                "avg_completion_tokens": 0 if i == 0 else reflection_completion_tokens / i,
                "error": "network error"
            }

        reflection_histories.append(reflection_history)
        reflection_prompt_tokens += response["usage"]["prompt_tokens"]
        reflection_completion_tokens += response["usage"]["completion_tokens"]
        responses.append(response)

        # Extract refined code
        refined_code = extract_code_from_content(response["choices"][0]["message"]["content"])

        if refined_code is None:
            print(f"Self-reflection failed: could not extract code from response")
            return {
                "code_path": code_path,
                "iterations": i + 1,
                "histories": reflection_histories,
                "responses": responses,
                "success": False,
                "reflection_times": i + 1,
                "avg_prompt_tokens": reflection_prompt_tokens / (i + 1),
                "avg_completion_tokens": reflection_completion_tokens / (i + 1),
                "error": "code extraction failed"
            }

        # Write refined code
        new_code_path = f"{os.path.dirname(code_path)}/{prefix}{i+1}_{llm_client}.sol"
        write_code_to_file(refined_code, new_code_path)
        code_path = new_code_path

        # Check syntax
        forge_cmd, compilable, errors = is_syntax_error_free(code_path)
        if not compilable:
            print(f"Self-reflection produced code with syntax errors, fixing...")
            syntax_result = refine_syntax(llm_client, code_path, "", max_iters=3, prefix=f"{prefix}{i+1}_syntax_")
            code_path = syntax_result['code_path']
            if syntax_result['iterations'] > 3:
                print(f"Self-reflection failed: could not fix syntax errors")
                continue

        # Test semantic correctness
        print(f"Testing self-reflected code...")
        forge_cmd, consistency, _ = is_semantic_error_free(code_path)

        if consistency:
            print(f"Self-reflection succeeded in {i+1} iterations!")
            return {
                "code_path": code_path,
                "iterations": i + 1,
                "forge_cmd": " ".join(forge_cmd),
                "histories": reflection_histories,
                "responses": responses,
                "avg_prompt_tokens": reflection_prompt_tokens / (i + 1),
                "avg_completion_tokens": reflection_completion_tokens / (i + 1)
            }
        else:
            continue

    # Max iterations reached without success
    print(f"Self-reflection completed {max_iters} iterations without success, will proceed to semantic refinement")
    return {
        "code_path": code_path,
        "iterations": max_iters,
        "histories": reflection_histories,
        "responses": responses,
        "avg_prompt_tokens": reflection_prompt_tokens / max_iters if max_iters > 0 else 0,
        "avg_completion_tokens": reflection_completion_tokens / max_iters if max_iters > 0 else 0
    }

def reflection(llm_client, 
               code_path, 
               user_prompt, 
               max_iters=3, 
               prefix="reflection_"):
    consistency = False
    responses= []
    reflection_prompt_tokens = 0
    reflection_completion_tokens = 0
    pre_code = read_code_from_file(code_path)
    
    for i in range(max_iters):
        forge_cmd, consistency, _ = is_semantic_error_free(code_path)
        if consistency:
            print(f"Self-reflection succeeded in {i} iterations!")
            return {
                "consistency": True,
                "code_path": code_path,
                "iterations": i,
                "forge_cmd": " ".join(forge_cmd),
                "responses": responses,
                "avg_prompt_tokens": reflection_prompt_tokens / i if i > 0 else 0,
                "avg_completion_tokens": reflection_completion_tokens / i if i > 0 else 0
            }
        else:
            reflection_result = refine_self_reflection(
                llm_client=llm_client,
                code_path=code_path,
                user_prompt=user_prompt,
                max_iters=1,
                prefix=f"{prefix}{i+1}_"
            )
            code_path = reflection_result["code_path"]
            responses.append(reflection_result["responses"][-1])
            reflection_prompt_tokens += reflection_result["avg_prompt_tokens"]
            reflection_completion_tokens += reflection_result["avg_completion_tokens"]
            
            forge_cmd, consistency, _ = is_semantic_error_free(code_path)
            if consistency:
                print(f"Self-reflection succeeded in {i+1} iterations!")
                return {
                    "consistency": True,
                    "code_path": code_path,
                    "iterations": i + 1,
                    "forge_cmd": " ".join(forge_cmd),
                    "histories": reflection_result["histories"],
                    "responses": responses,
                    "avg_prompt_tokens": reflection_prompt_tokens / (i + 1),
                    "avg_completion_tokens": reflection_completion_tokens / (i + 1)
                }
            code = read_code_from_file(code_path)
            if code == pre_code:
                print(f"Self-reflection did not produce new code, stopping early at iteration {i+1}.")
                break
            else:
                pre_code = code
    return {
        "consistency": False,
        "code_path": code_path,
        "iterations": i + 1,
        "histories": reflection_result["histories"],
        "responses": responses,
        "avg_prompt_tokens": reflection_prompt_tokens / max_iters if max_iters > 0 else 0,
        "avg_completion_tokens": reflection_completion_tokens / max_iters if max_iters > 0 else 0
    }

def refine_semantic(llm_client, 
                    code_path, 
                    ref_callgraph, 
                    text_irs, 
                    syn_sys_prompt, 
                    syn_user_prompt, 
                    max_iters=5, 
                    prefix="refine_semantic_"):
    consistency = False
    diff_histories = []
    semantic_histories = []
    responses = []
    semantic_prompt_tokens = 0
    semantic_completion_tokens = 0
    for i in range(max_iters):
        forge_cmd, consistency, result = is_semantic_error_free(code_path)
        if consistency:
            return {
                "consistency": True,
                "code_path": code_path,
                "forge_cmd": " ".join(forge_cmd),
                "differences": diff_histories,
                "iterations": i,
                "histories": semantic_histories,
                "responses": responses,
                "avg_prompt_tokens": 0 if i == 0 else semantic_prompt_tokens/i,
                "avg_completion_tokens": 0 if i == 0 else semantic_completion_tokens / i
            }
        else:
            diffs = calltrace_diff(result, ref_callgraph)
            diff_histories.append(diffs)
            if diffs.startswith("setup failed"):
                return {
                    "consistency": False,
                    "code_path": code_path,
                    "differences": diff_histories,
                    "iterations": i,
                    "histories": semantic_histories,
                    "responses": responses,
                    "avg_prompt_tokens": 0 if i == 0 else semantic_prompt_tokens/i,
                    "avg_completion_tokens": 0 if i == 0 else semantic_completion_tokens / i,
                    "error": diffs 
                }                
            
            print(f"Semantic refinement failed in {i+1} iterations, trying to fix the semantic errors:\n{diffs}.")
            code = read_code_from_file(code_path)
            ori_prompt = make_prompt(llm_client, sys_prompt=syn_sys_prompt, user_prompt=syn_user_prompt)
            ass_prompt = make_prompt(llm_client, prompt=ori_prompt, assist_prompt=code)
            user_prompt = semantic_user_prompt
            user_prompt = user_prompt.format(differences=diffs)
            prompt = make_prompt(llm_client, prompt=ass_prompt, user_prompt=user_prompt)
            response, semantic_history = make_request(llm_client, prompt)
            if response:
                semantic_histories.append(semantic_history)
                semantic_prompt_tokens += response["usage"]["prompt_tokens"]
                semantic_completion_tokens += response["usage"]["completion_tokens"]
                responses.append(response)
                code = extract_code_from_content(response["choices"][0]["message"]["content"])
        
                assert code is not None, "Failed to extract code from response."
                code_path = f"{os.path.dirname(code_path)}/{prefix}{i+1}_{llm_client}.sol"
                write_code_to_file(code, code_path)
                
                forge_cmd, compilable, _ = is_syntax_error_free(code_path)
                if not compilable:
                    syntax_result = refine_syntax(llm_client, code_path, text_irs, max_iters=5, prefix=f"{prefix}{i+1}_syntax_")
                    code_path = syntax_result['code_path']

            else:
                return {
                    "consistency": False,
                    "code_path": code_path,
                    "differences": diff_histories,
                    "iterations": i,
                    "histories": semantic_histories,
                    "responses": responses,
                    "avg_prompt_tokens": 0 if i == 0 else semantic_prompt_tokens/i,
                    "avg_completion_tokens": 0 if i == 0 else semantic_completion_tokens / i,
                    "error": "network error"
                }

    forge_cmd, consistency, result = is_semantic_error_free(code_path)
    if consistency:
       return {
            "consistency": True,
            "code_path": code_path,
            "forge_cmd": " ".join(forge_cmd),
            "differences": diff_histories,
            "iterations": max_iters,
            "histories": semantic_histories,
            "responses": responses,
            "avg_prompt_tokens": semantic_prompt_tokens/max_iters,
            "avg_completion_tokens": semantic_completion_tokens/max_iters
        }
    else:
        diffs = calltrace_diff(result, ref_callgraph)
        diff_histories.append(diffs)
            
        return {
            "consistency": False,
            "code_path": code_path,
            "differences": diff_histories,
            "iterations": max_iters + 1,
            "histories": semantic_histories,
            "responses": responses,
            "avg_prompt_tokens": semantic_prompt_tokens/max_iters,
            "avg_completion_tokens": semantic_completion_tokens/max_iters
        }
        
        print(f"Semantic refinement failed after {max_iters} iterations.")
        return code_path, diffs, max_iters, semantic_histories, responses

def is_syntax_error_free(code_path, var_ir=False):
    root_path = f"{CACHE_DIR}/result"
    stderr_path = f"{code_path.replace('.sol', '.compile.stdeer')}"
    stdout_path = f"{code_path.replace('.sol', '.compile.stdout')}"
    forge_cmd = ["forge", "test", "--root", root_path, "--contracts", os.path.relpath(code_path, root_path)]
    evm_version = read_evm_version_from_code_file(code_path)
    if evm_version != "default":
        forge_cmd += ["--evm-version", evm_version]

    run_cmd(forge_cmd, stdout=stdout_path, stderr=stderr_path)
    errors = read_errors(stderr_path)
    if len(errors) > 0: # it means the code has syntax errors
        if "--via-ir" in errors:
            forge_cmd += ["--via-ir"]
            run_cmd(forge_cmd, stdout=stdout_path, stderr=stderr_path)
            errors = read_errors(stderr_path)
            if len(errors) > 0:
                return forge_cmd, False, errors
            else:
                return forge_cmd, True, ""
        return forge_cmd, False, errors
    
    else:
        errors = read_errors(stdout_path)
        if len(errors) > 0:
            return forge_cmd, False, errors
        return forge_cmd, True, ""

def refine_syntax(llm_client, code_path, text_irs, max_iters=5, prefix="refine_syntax_"):
    """
    return the refined syntax error-free code_path
    """
    # global syntax_user_prompt
    dst_dir = os.path.dirname(code_path)
    compilable = False
    errors_history = []
    syntax_histories = []
    responses = []
    syntax_prompt_tokens = 0
    syntax_completion_tokens = 0
    for i in range(max_iters):
        forge_cmd, compilable, errors = is_syntax_error_free(code_path)
        errors_history.append(errors)
        if compilable:
            return {
                "code_path": code_path,
                "forge_cmd": " ".join(forge_cmd),
                "errors_history": errors_history,
                "iterations": i,
                "histories": syntax_histories,
                "responses": responses,
                "avg_prompt_tokens": 0 if i == 0 else syntax_prompt_tokens/i,
                "avg_completion_tokens": 0 if i == 0 else syntax_completion_tokens / i
            }
            # print(f"Syntax refinement completed in {i} iterations.")
            return code_path, errors_history, i, syntax_histories, responses, 0 if i == 0 else syntax_prompt_tokens/i, 0 if i == 0 else syntax_completion_tokens / i
        
        else:
            # print(f"Syntax refinement failed in {i+1} iterations, trying to fix the syntax errors {errors}.")
            code = read_code_from_file(code_path)
            user_prompt = syntax_user_prompt
            user_prompt = user_prompt.format(code=code, executions=text_irs, errors=errors)
            prompt = make_prompt(llm_client, sys_prompt=syntax_sys_prompt, user_prompt=user_prompt)
            response, syntax_history = make_request(llm_client, prompt)
            if response:
                syntax_prompt_tokens += response["usage"]["prompt_tokens"]
                syntax_completion_tokens += response["usage"]["completion_tokens"]
                responses.append(response)
                syntax_histories.append(syntax_history)
                code = extract_code_from_content(response["choices"][0]["message"]["content"])
        
                assert code is not None, "Failed to extract code from response."
                code_path = f"{dst_dir}/{prefix}{i+1}_{llm_client}.sol"
                write_code_to_file(code, code_path)
            else:
                return {
                    "code_path": code_path,
                    "errors_history": errors_history,
                    "iterations": i,
                    "histories": syntax_histories,
                    "responses": responses,
                    "avg_prompt_tokens": 0 if i == 0 else syntax_prompt_tokens/i,
                    "avg_completion_tokens": 0 if i == 0 else syntax_completion_tokens / i,
                    "error": "network error"
                }


    forge_cmd, compilable, errors = is_syntax_error_free(code_path)
    errors_history.append(errors)
            
    if compilable:
        return {
            "code_path": code_path,
            "forge_cmd": " ".join(forge_cmd),
            "errors_history": errors_history,
            "iterations": max_iters,
            "histories": syntax_histories,
            "responses": responses,
            "avg_prompt_tokens": syntax_prompt_tokens/max_iters,
            "avg_completion_tokens": syntax_completion_tokens/max_iters
        }
        # return code_path, errors_history, max_iters, syntax_histories, responses, syntax_prompt_tokens/max_iters, syntax_completion_tokens/max_iters
    else:
        return {
            "code_path": code_path,
            "forge_cmd": " ".join(forge_cmd),
            "errors_history": errors_history,
            "iterations": max_iters + 1,
            "histories": syntax_histories,
            "responses": responses,
            "avg_prompt_tokens": syntax_prompt_tokens/max_iters,
            "avg_completion_tokens": syntax_completion_tokens/max_iters
        }
        # return code_path, errors_history, max_iters + 1, syntax_histories, responses, syntax_prompt_tokens/max_iters, syntax_completion_tokens/max_iters