import time

import panoramix.settings as settings
from panoramix.loader import LOADER_TIMEOUT, Loader
from panoramix.optimization import co_cleanup
from panoramix.prettify import explain, pprint_trace
from panoramix.rewriter import rewrite_call_args
from panoramix.simplify import (cleanup_conds, cleanup_loops, cleanup_mems,
                                cleanup_vars, if_to_require, loop_to_setmem,
                                simplify_exp, split_setmem, split_store)
from panoramix.utils.helpers import (COLOR_BLUE, ENDC, C, cached, get_concrete,
                                     opcode, replace_f, rewrite_trace,
                                     rewrite_trace_full, sampling_range,
                                     sampling_trace, time_profile)
from panoramix.utils.supplement import fetch_sig
from panoramix.vm import VM
from tracexp.hooks import add_concrete_hook, add_pc, add_pc_hook, get_param_hook
from tracexp.utils.helpers import decode_abi, decode_output


@cached
def sim(exp):
    return [simplify_exp(exp)]

def simplify_trace(trace):
    """
    Simplify a trace by removing unnecessary variables and mems.
    """
    # # to test the effectiveness of support_concrete, set it to true/false
    if settings.tracexp_as_1:
        settings.set_from_string("support_concrete", "false")

    trace = rewrite_trace_full(trace, split_store)
    explain("split storages", trace)
       
    trace = co_cleanup(trace)
    explain("co cleanup trace", trace)
    
    # if settings.tracexp_as_1:
    #     # when the loop times is 0 or 1, it can be flatted
    #     trace = rewrite_trace(trace, cleanup_loops)
    #     explain("cleanup loops", trace)
        
    #     # TODO: set mem
    #     # here, some setvar in loops are reduced
    #     trace = rewrite_trace(trace, loop_to_setmem)
    #     explain("convert loops to setmems", trace)
        
    #     trace = cleanup_vars(trace)
    #     explain("cleanup variables", trace)
            
    #     trace = cleanup_mems(trace)
    #     explain("cleanup mems", trace)

    # else:
    #     trace = co_cleanup(trace, debug=False)
    #     explain("co copy propagation", trace)
       
    trace = cleanup_conds(trace)
    explain("cleanup unused ifs", trace)
    
    trace = rewrite_trace_full(trace, rewrite_call_args)
    explain("rewrite call args", trace)
    
    # # to test the effectiveness of support_concrete, set it to true/false
    if settings.tracexp_as_1:
        settings.set_from_string("support_concrete", "true")

    return trace

def _decompile_with_loader(loader:Loader, is_constructor=False, verbose=settings.explain):
    if not settings.tracexp_as_1:
        hooks = [add_pc_hook, add_concrete_hook]
    else:    
        hooks = [add_pc_hook]
    if is_constructor:
        loader.func_dests = {"constructor": 0}
        loader.func_list = [('constructor', 'constructor()', 0, (), -1)]
        loader.hash_targets = {'constructor': (0, ())}
    else:
        trace = VM(loader, just_fdests=True, hooks=hooks).run(0)
        loader._run(trace)
        if len(loader.func_list) > 1 and loader.func_list[-1][0] == '_fallback':
            loader.func_list.pop()
        
        if verbose:
            explain("Initial decompiled trace", trace[1:])
        
    assert len(loader.func_list) >= 1, "At least one function is dispatched in the trace."
    
    _, fname, target, stack, trace_idx = loader.func_list[-1]
    
    try:
        if target > 1 and loader.lines[target][1] == "jumpdest":
            target += 1

        def dec():
            trace = VM(loader, hooks=hooks).run(trace_idx + 1, stack = stack)
            
            if verbose:
                explain("Initial decompiled trace", trace[1:])

            if verbose:
                trace = rewrite_trace(
                    trace, lambda line: [] if type(line) == str else [line]
                )
                explain("Without assembly", trace)
            
            trace = simplify_trace(trace) # todo: tailor this make_while function

            return trace

        trace = dec()
        
        return trace
                
    except Exception as e:
        # import traceback
        # traceback.print_exc()
        # return None
        raise e
        print(f"Problem with {e}", fname)

def parse_trace(trace, is_constructor):
    """
    Parse the trace to extract the relevant information.
    """
    # This function should be implemented to extract the relevant information from the trace.
    # For now, we will just return the trace as is.
    loader = Loader()
    loader.load_trace(trace, get_param_hook)

    decompilation = _decompile_with_loader(loader, is_constructor, verbose=True)
    
    return decompilation

def explainer(trace_list, _explain:bool=False, wo_adv_contracts:bool=False):
    """
    Lift concrete traces to symbolic high-level functions.   
    """
    if _explain:
        settings.set_from_string("explain", "true")

    settings.set_from_string("prettify_concrete", "false")
    settings.set_from_string("prettify_pc", "false")
    settings.set_from_string("assume_len", "false")
    settings.set_from_string("prunning_ifs", "true")
    settings.set_from_string("prettify_call_toself", "true")

    ir_list = []
    for i, (callee, _input, trace) in enumerate(trace_list):
        depth, call, input, value = _input.split("_")
        if call == "STATICCALL": # keep the static calls
            if trace and len(trace) > 0 and (last_line := trace[-1]) and last_line['opName'] == "RETURN":
                output = last_line['output']
                sig = input[:10]
                output = decode_output(sig, output) if sig != "0x" else output
                line = ("return", output if output else "0x")
                # line = ("return", output if output else "0x")
                pc = last_line['pc']
                
                ir = [add_pc(line, pc)]
            else:
                continue
        else:    
            output = "" if not (trace and len(trace) > 0 and trace[-1]['opName'] == "RETURN") else trace[-1]['output'][:20]
            is_constructor = (call in ("CREATE", "CREATE2"))
            
            if not is_constructor:        
                print(C.blue_back + f"Parsing trace: {callee}.{decode_abi(input[:10], input[10:])}{' -> ' + output[:20] + '...' if len(output) > 20 else ' -> ' + output if len(output) > 0 else output}" + C.end)
            else:
                print(C.blue_back + f"Parsing constructor trace: {callee}" + C.end)
            s = time.monotonic()
            if wo_adv_contracts:
                ir = []
            else:
                ir = parse_trace(trace, is_constructor=is_constructor)
        ir_list.append((callee, _input, ir))
        
        if _explain:
            explain("Decompiled trace", ir, print_anyway=True)
        
        print(f"Parsed trace {i + 1}/{len(trace_list)} in {time.monotonic() - s:.2f} seconds")

    return ir_list