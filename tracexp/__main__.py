import os
import sys

sys.path.append(os.getcwd())

import argparse

# from panoramix.prettify import explain, pprint_trace
import panoramix.settings as settings

settings.configure_from_all_sources()
settings.support_concrete = True
settings.ignore_conds = True
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from tracexp.compressor import compressor
from tracexp.explainer import explainer
from tracexp.locator import locator
from tracexp.refiner import refine_semantic, refine_syntax, reflection
from tracexp.synthesizer import (synthesizer_deals, synthesizer_oracles,
                             synthesizer_poc, synthesizer_prompt)
from tracexp.tracer import trace_from_tx_hash
from tracexp.utils import (CACHE_DIR, DST_DIR, Records, check_contract_abi,
                       extract_code_from_content, get_transaction_blocknumber,
                       get_transaction_value, get_valid_code,
                       prepare_foundry_files, to_checksum_address,
                       write_code_to_file)


def parse_args():
    parser = argparse.ArgumentParser(description="Trace-based exploit synthesis")
    parser.add_argument(
        "--chain",
        type=str,
        default="eth",
        help="Chain to analyze (e.g., eth, bsc, etc.)",
    )
    parser.add_argument(
        "--tx-hashes",
        type=str,
        nargs='+',
        help="Attack transactions list to analyze, delimited by commas",
    )
    parser.add_argument(
        "--to-vuls",
        type=int,
        nargs='+',
        default=None,
        help="true iff the given transactions are sent to vulnerable contracts",
    )
    parser.add_argument("--attacker", type=str, default=None, help="Attacker address (benificiary, default the sender)")
    parser.add_argument("--llm-client", type=str, default="gpt-5", help="LLM client to use for synthesis")
    parser.add_argument("--only-static", action="store_true", help="Only run static analysis without LLM synthesizer")
    parser.add_argument("--only-synthesizer", action="store_true", help="Only run the LLM synthesizer without tracing or analysis")    
    parser.add_argument('--ablation-study', type=int, choices=[-1, 1, 2], default=-1, help='Run ablation study version of TracExp. Choices are 1, 2, or 3.')
    parser.add_argument("--force-rerun", action="store_true", help="Force rerun the synthesizer even if cached results exist")
    parser.add_argument("--force-refine", action="store_true", help="Force rerun the refiner even if cached results exist")
    parser.add_argument("--syntax-iters", type=int, default=5, help="Number of iterations for syntax refinement")
    parser.add_argument("--reflection-iters", type=int, default=3, help="Number of iterations for reflection refinement")
    parser.add_argument("--semantic-iters", type=int, default=3, help="Number of iterations for semantic refinement")
    parser.add_argument("--callee", type=str, default=None, help="Callee contract to analyze")
    parser.add_argument("--func", type=str, default=None, help="Function to analyze")
    parser.add_argument("--trace-idx", type=int, default=None, help="Index of the trace to analyze")
    parser.add_argument("--attc", type=str, default=None, help="attack contract to analyze")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--no-refine", action="store_true", help="Do not run the refinement steps after synthesis")
    parser.add_argument("--no-reflection", action="store_true", help="Do not run the reflection steps after synthesis")
    parser.add_argument("--no-semantic-refine", action="store_true", help="Do not run the semantic refinement steps after synthesis")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    dst_dir = f"{DST_DIR}/{args.chain}/{args.tx_hashes[0]}"
    os.makedirs(dst_dir, exist_ok=True)
    prepare_foundry_files(os.path.dirname(dst_dir))
    
    records_path = f"{dst_dir}/records.json"
    if args.ablation_study == 1:
        records_path = f"{dst_dir}/records_wo_concrete.json"
        settings.tracexp_as_1 = True
        args.only_static = True
    elif args.ablation_study == 2:
        records_path = f"{dst_dir}/records_wo_compressor.json"
        settings.tracexp_as_2 = True
        args.only_static = True

    to_vuls = args.to_vuls if args.to_vuls is not None else [0] * len(args.tx_hashes)

    if args.force_rerun or not args.only_synthesizer:
        if not args.force_rerun and os.path.exists(records_path):
            print(f"Records file {records_path} already exists. Loading existing records.")
            sys.exit(0)
        
        records = Records(records_path)
        records.record_metrics({
            "chain": args.chain,
            "tx_hashes": args.tx_hashes,
            "to_vuls": to_vuls,
        })

        # for each transaction hash, we will trace the attack, the tx_irs is List[List[(contract, depth_call_input, trace)]]
        tx_irs = []
        senders = []
        receivers = []
        values = []
        
        oracles = []
        blocknumbers = []
        tx_inputs = []
        callgraphs = []
        support_revert = False
        with records.measure_time("total"):
            num_ins = 0
            max_ins = -1
            for tx_hash, to_vul in zip(args.tx_hashes, to_vuls):
                print("Processing transaction:", tx_hash)
                with records.measure_time("trace_from_tx_hash"):
                    efg = trace_from_tx_hash(
                        chain=args.chain,
                        tx_hash=tx_hash,
                        tracer="efgTracer"
                    )
                    support_revert = support_revert | any(op['opName'] == 'REVERT' for g in efg for op in g['ops'])
                    oracle = trace_from_tx_hash(
                        chain=args.chain,
                        tx_hash=tx_hash,
                        tracer="oracleTracer"
                    )
                    tx_input = efg[0]['input']
                    sender = efg[0]['sender']
                    receiver = efg[0]['contract']
                    
                    value = int(efg[0]['value']) / 1e18
                    num_ins += sum(len(e["ops"]) for e in efg)
                    blocknumber = get_transaction_blocknumber(args.chain, tx_hash)

                    records.record_metrics({
                        "efg_node_count":len(efg),
                        "efg_contract_count":len(set([node['contract'] for node in efg])),
                        "support_revert": support_revert,}
                    )
                    
                with records.measure_time("locator"):
                    attack_pattern, traces, callgraph = locator(
                        efg=efg,
                        dump_trace_dir=f"{CACHE_DIR}/instrument/{args.chain}/{tx_hash}",
                        attc=args.attc,
                        func=args.func,
                        idx=args.trace_idx,
                        wo_adv_contracts=to_vul==1,
                        # viscallgraph=True
                    )
                    for trace in traces:
                        if (ins := len(trace[-1])) > max_ins:
                            max_ins = ins
                    records.record_metrics(attack_pattern)
                    records.record_metrics({
                        "trace_count": len(traces),
                        "max_trace_length": max([len(trace) for _, _, trace in traces] + [0,])
                        }
                    )
                    check_contract_abi(args.chain, set([node['contract'] for node in efg]))

                with records.measure_time("explainer"):
                    # we add the ablation study 1 in the simplify_trace function of explainer
                    irs = explainer(traces, _explain=args.explain, wo_adv_contracts=to_vul==1)
        
                if args.ablation_study != 2:
                    with records.measure_time("compressor"):
                        settings.prettify_call_idx = True
                        settings.assume_require = True
                        max_loops, compressed_irs = compressor(irs, _explain=args.explain)
                        records.record_metrics({
                            "max_loops": max_loops,
                        })
                        
                    tx_irs.append(compressed_irs)
                else:
                    tx_irs.append(irs) # for ablation study, the irs without compression is pushed
                oracles.extend(oracle)
                tx_inputs.append(tx_input)
                senders.append(to_checksum_address(sender))
                receivers.append(to_checksum_address(receiver))
                values.append(value)
                blocknumbers.append(blocknumber)
                callgraphs.append(callgraph)
            
            records.record_metrics({
                "num_ins": num_ins,
                "max_ins": max_ins,
                "callgraph": callgraphs
            })
            
            with records.measure_time("synthesizer_draft"):
                settings.assume_require = False
                settings.prettify_call_idx = False 
                               
                attacker = args.attacker if args.attacker is not None else senders[0]
                # default the benificiary to the sender of the first transaction
                receiver = receivers[0]

                # tx_inputs for locate the root in the callgraph
                deals, attack_deals, pre_attack_log, post_attack_log, setup_approves, approves = synthesizer_oracles(
                    args.chain, oracles, attacker, receiver, blocknumbers=blocknumbers, tx_inputs = "".join(tx_inputs).lower(), callgraph=callgraphs[0] if len(callgraphs) > 0 else None
                )

                blocknumbers.append(blocknumber)

                sys_prompt, user_prompt, attacks_in_params, text_irs = synthesizer_prompt(chain=args.chain,
                                                                                          blocknumbers=blocknumbers,
                                                                                          deals=deals,
                                                                                          attack_deals=attack_deals,
                                                                                          pre_attack_logs=pre_attack_log,
                                                                                          senders=senders,
                                                                                          receiver=receiver,
                                                                                          irs=tx_irs,
                                                                                          values=values,
                                                                                          post_attack_logs=post_attack_log,
                                                                                          wo_adv_contracts=all(to_vul==1 for to_vul in to_vuls),
                                                                                          support_revert=support_revert,
                                                                                          setup_approves=setup_approves,
                                                                                          approves=approves)
                records.record_metrics({
                    "sys_prompt": sys_prompt,
                    "user_prompt": user_prompt,
                    "attacks_in_params": attacks_in_params,
                    "text_irs": text_irs,
                    "with_deals": int(len(deals) > 0 or len(attack_deals) > 0),
                    "with_logs": int(len(pre_attack_log) > 0 or len(post_attack_log) > 0)
                })
                records.save_record("user_prompt", suffix=f"as_{args.ablation_study}" if args.ablation_study != -1 else "")
                records.save_record("sys_prompt", suffix=f"as_{args.ablation_study}" if args.ablation_study != -1 else "")
    
        records.summary()
    
    if not args.only_static:
        records = Records(records_path)
        records.load()
        sys_prompt, user_prompt = records.get_record("sys_prompt"), records.get_record("user_prompt")
        assert sys_prompt and user_prompt, "System or user prompt is missing in records."
        if records.get_record(f"synthesis_status_{args.llm_client}"):
            synthesis_code_path = records.get_record(f"synthesis_code_path_{args.llm_client}")
            print(f"Using cached synthesized code for {args.llm_client}")
            assert synthesis_code_path and os.path.exists(synthesis_code_path), "Cached synthesized code path is invalid."
        else:
            with records.measure_time(f"synthesizer_poc_{args.llm_client}"):
                synthesis_code_path = f"{dst_dir}/syn_code_{args.llm_client}.sol"
                synthesizer_result = synthesizer_poc(
                    sys_prompt=sys_prompt,
                    user_prompt=user_prompt,
                    llm_client=args.llm_client,  # Assuming you have a configured LLM client
                    code_path=synthesis_code_path
                )
                if synthesizer_result['code_path'] is not None:
                    records.add_record(f"synthesis_status_{args.llm_client}", 1)
                    print(f"Synthesis completed for {args.llm_client}.")
                else:
                    records.add_record(f"synthesis_status_{args.llm_client}", 0)
                    print(f"Synthesis failed for {args.llm_client}.")
                    sys.exit(0)
                records.record_metrics({f"synthesis_{k}_{args.llm_client}":v for k, v in synthesizer_result.items()})

        if args.no_refine:
            records.summary()
            sys.exit(0)
    
        if records.get_record(f"synthesis_status_{args.llm_client}", 0):
            print(f"Synthesized code for {args.llm_client} is available at {synthesis_code_path}")
        
            if records.get_record(f"syntax_status_{args.llm_client}"):
                syntax_code_path = records.get_record(f"syntax_code_path_{args.llm_client}")
                print(f"Using cached syntax refined code for {args.llm_client}")
            else:
                with records.measure_time(f"refine_syntax_{args.llm_client}"):
                    text_irs = records.get_record("text_irs")
                    assert text_irs is not None and len(text_irs) > 0, "text_irs is missing in records."
                    syntax_result = refine_syntax(
                        args.llm_client, synthesis_code_path, text_irs, args.syntax_iters)
                    # syntax_code_path, syntax_errors, syntax_iters, syntax_history, responses, syntax_avg_prompt_tokens, syntax_avg_comp_tokens = refine_syntax(args.llm_client, synthesis_code_path, text_irs, args.syntax_iters)
                    syntax_code_path = syntax_result['code_path']
                    syntax_iters = syntax_result['iterations']
                    if syntax_iters <= args.syntax_iters:
                        records.add_record(f"syntax_status_{args.llm_client}", 1)
                        print(f"Syntax refinement completed in {syntax_iters} iterations.")
                    else:
                        records.add_record(f"syntax_status_{args.llm_client}", 0)
                        print(f"Syntax refinement failed after {syntax_iters} iterations.")
                        assert False, "Syntax refinement failed after maximum iterations."
                    records.record_metrics({f"syntax_{k}_{args.llm_client}":v for k, v in syntax_result.items()})

            if records.get_record(f"syntax_status_{args.llm_client}", 0):
                print(f"Syntax refined code for {args.llm_client} is available at {syntax_code_path}")
                sys_prompt, user_prompt = records.get_record("sys_prompt"), records.get_record("user_prompt")
                assert sys_prompt and user_prompt, "System or user prompt is missing in records."

                semantic_prefix = "w_reflection" if not args.no_reflection else "wo_reflection"
        
                if args.no_reflection and records.get_record(f"reflection_status_{args.llm_client}", 0):
                    semantic_code_path = records.get_record(f"reflection_semantic_code_path_{args.llm_client}")
                    print(f"Using cached semantic refined code with reflection for {args.llm_client}")
                elif records.get_record(f"semantic_{semantic_prefix}_status_{args.llm_client}", 0):
                    semantic_code_path = records.get_record(f"semantic_{semantic_prefix}_code_path_{args.llm_client}")
                    print(f"Using cached semantic refined code with semantic refinement for {args.llm_client}")
                else:
                    if not args.no_reflection:
                        status = records.get_record(f"reflection_status_{args.llm_client}")
                        if status is None:
                            print(f"Reflection refinement has not been run for {args.llm_client}. Running reflection refinement.")
                            with records.measure_time(f"refine_semantic_reflection_{args.llm_client}"):
                                reflection_result = reflection(
                                    args.llm_client, syntax_code_path, user_prompt, max_iters=args.reflection_iters)
                                reflection_code_path = reflection_result['code_path']
                                reflection_iters = reflection_result['iterations']
                                if reflection_iters <= args.reflection_iters and reflection_result.get("consistency", False):
                                    records.add_record(f"reflection_status_{args.llm_client}", 1)
                                    print(f"Reflection refinement completed in {reflection_iters} iterations.")
                                else:
                                    records.add_record(f"reflection_status_{args.llm_client}", 0)
                                    print(f"Reflection refinement failed after {reflection_iters} iterations.")
                                records.record_metrics({f"reflection_{k}_{args.llm_client}":v for k, v in reflection_result.items()})
                        
                        else:
                            syntax_code_path = records.get_record(f"reflection_code_path_{args.llm_client}", syntax_code_path)
                            print(f"Using cached reflection refined code at {syntax_code_path} for {args.llm_client}")
                    else:
                        syntax_code_path = records.get_record(f"syntax_code_path_{args.llm_client}", syntax_code_path)
                        print(f"Reflection refinement skipped for {args.llm_client} due to no_reflection flag.")
                    
                    if not args.no_semantic_refine:                    
                        with records.measure_time(f"refine_semantic_{semantic_prefix}_{args.llm_client}"):
                            ref_callgraph = records.get_record("callgraph")
                            if isinstance(ref_callgraph, list) and len(ref_callgraph) > 0:
                                ref_callgraph = ref_callgraph[0]
                            text_irs = records.get_record("text_irs")
                            semantic_result = refine_semantic(
                                args.llm_client, syntax_code_path, ref_callgraph, text_irs, sys_prompt, user_prompt, max_iters=args.semantic_iters, prefix=f"refine_semantic_{semantic_prefix}_")
                            semantic_code_path = semantic_result['code_path']
                            semantic_iters = semantic_result['iterations']
                            # semantic_code_path, semantic_diffs, semantic_iters, semantic_history, responses = refine_semantic(args.llm_client, syntax_code_path, ref_callgraph, text_irs, args.semantic_iters)
                            if semantic_iters <= args.semantic_iters and semantic_result.get("consistency", False):
                                records.add_record(f"semantic_{semantic_prefix}_status_{args.llm_client}", 1)
                                print(f"Semantic refinement completed in {semantic_iters} iterations.")
                            else:
                                records.add_record(f"semantic_{semantic_prefix}_status_{args.llm_client}", 0)
                                print(f"Semantic refinement failed after {semantic_iters} iterations.")
                            records.record_metrics({f"semantic_{semantic_prefix}_{k}_{args.llm_client}":v for k, v in semantic_result.items()})
                            
                            
                        if records.get_record(f"semantic_{semantic_prefix}_status_{args.llm_client}") == 0:
                            if len(semantic_result.get("error", "")) > 0:
                                reason = f"semantic_{semantic_prefix}_error_{args.llm_client}"

                            elif semantic_iters > args.semantic_iters:
                                reason = "max_iters_exceeded"
                                
                            else:
                                reason = "unknown"
                            
                            assert False, reason
            else:
                print(f"Semantic refinement skipped for {args.llm_client} due to syntax errors.")
        else:
            print(f"Synthesized code for {args.llm_client} is not available, skipping refinement.")

        records.summary()
        valid_code = get_valid_code(dst_dir, args.llm_client)
        assert valid_code is not None and valid_code >= 4, "Final synthesized code did not pass validation. Please check the records for details."