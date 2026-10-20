import json
import os
import warnings

from tracexp.tracer import dumps_trace
from tracexp.utils.visualizer import visualize_call_graph

# not used
def deduplicate_traces(trace_list):
    """
    Deduplicate traces based on the `pc`.
    """
    seen = set()
    unique_traces = []
    
    def get_trace_ops(op_list):
        # return ''.join([f"{op['pc']}" for op in op_list])
        return json.dumps([op['pc'] for op in  op_list])
        ops = tuple()
        for op in op_list:
            opName = op['opName']
            pc = op['pc']
            if opName.startswith("PUSH"):
                args = op['pushes'][-1]
                if isinstance(args, str):
                    if not args.startswith("0x"):
                        args = "0x" + value
                    args = int(args, 16)

                ops += ((pc, opName, args),)
            else:
                ops += ((pc, opName),)
        return ops

    for trace in trace_list:
        ops = get_trace_ops(trace)
        if ops not in seen:
            seen.add(ops)
            unique_traces.append(trace)
    
    return unique_traces

def hash_ops(op_list):
    return hash(tuple([op['pc'] for op in op_list]))

def expand_callees(root_callee, calltree):
    """Expand attacker-controlled callees by traversing the calltree.

    Starting from root_callee, follows CREATE/CREATE2 and DELEGATECALL edges to
    determine which contracts are under the attacker's control.  Regular CALLs
    are not followed (the callee is considered external), but their subtrees are
    still traversed so that reentrancy back into an in-scope contract is found.

    Returns:
        result   : list of (contract, composite_input_key) pairs in scope.
        max_depth: maximum EVM call depth observed across in-scope nodes.
    """
    result = []
    max_depth = -1
    seen = set()
    in_scope_contracts = {root_callee}

    def _node_input_key(node):
        v = node.get('value')
        eth_value = int(v or '0') / 1e18
        return f"{node['depth']}_{node['call']}_{node['input']}_{eth_value}"

    def _traverse(node):
        nonlocal max_depth
        contract = node['contract']

        if contract in in_scope_contracts:
            key = _node_input_key(node)
            max_depth = max(max_depth, node['depth'])
            entry = (contract, key)
            if entry not in seen:
                seen.add(entry)
                result.append(entry)

            # Expand scope: contracts deployed via CREATE/CREATE2 or executed
            # via DELEGATECALL are also attacker-controlled.
            for child in node.get('children', []):
                if child['call'] in ('CREATE', 'CREATE2', 'DELEGATECALL'):
                    in_scope_contracts.add(child['contract'])

        # Always recurse into every child so that reentrancy (an in-scope
        # contract reached through an out-of-scope external call) is captured.
        for child in node.get('children', []):
            _traverse(child)

    _traverse(calltree)
    return result, max_depth

def get_callee_centric_execution_path(efg):
    """
    Get the callee-centric execution path from the EFGs, and also deduplicate same execution path.

    Returns:
        ccep (dict): A dictionary where keys are contracts and values are dictionaries of
                     composite input keys and their corresponding execution-path op lists.
                     Composite key format: "{depth}_{call}_{calldata}_{eth_value}"
    """
    assert len(efg) > 0, "The execution flow graph (EFG) is empty."

    ccep = {}

    for node_idx, node in enumerate(efg):
        _depth, _contract, _call, _input, _value, _ops = node['depth'], node['contract'], node['call'], node['input'], int(node.get('value', '0')) / 1e18, node['ops']

        _input = f"{_depth}_{_call}_{_input}_{_value}"

        if _contract not in ccep:
            ccep[_contract] = {_input: [_ops]}

        else:
            if _input not in ccep[_contract]:
                ccep[_contract][_input] = [_ops]
            else:
                current_last_op = ccep[_contract][_input][-1][-1]

                if _ops[0]['pc'] == current_last_op['pc'] + 1:
                    if current_last_op['opName'] in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL") and \
                        node_idx > 1 and (prev_op:=efg[node_idx - 1]['ops'][-1]) and prev_op['opName'] == "RETURN" and len(prev_op['output']) > 0:
                            ccep[_contract][_input][-1][-1]['output'] = prev_op['output']

                    elif current_last_op['opName'] in ("CREATE", "CREATE2") and \
                        node_idx > 1 and (prev_op:=efg[node_idx - 1]['ops'][-1]) and prev_op['opName'] in ("RETURN", "STOP", "SELFDESTRUCT"):
                            # The segment immediately before the resume is the created contract's
                            # last segment, so its 'contract' field is the deployed address.
                            ccep[_contract][_input][-1][-1]['output'] = efg[node_idx - 1]['contract']

                    ccep[_contract][_input][-1].extend(_ops)
                else:
                    assert _ops[0]['pc'] == 0 or node['call'] == "STATICCALL", f"Unexpected PC jump in trace at node_idx {node_idx}."
                    ccep[_contract][_input].append(_ops)

    return ccep

def attack_pattern(attack_scope):
    with_new_contract = False
    with_delegate_calls = False
    with_callback = False
    with_long_input = False
    input_length = -1

    contract_depth = {}

    if len(attack_scope) > 0:
        for i, (contract, input) in enumerate(attack_scope):
            depth, call, _input, _ = input.split('_')
            if i == 0:
                if len(_input) > 2 + 8 + 64 * 20:
                    with_long_input = True
                    input_length = len(_input)

            if call in ("CREATE", "CREATE2"):
                with_new_contract = True
            elif call in ("DELEGATECALL", ):
                with_delegate_calls = True
                
            if contract not in contract_depth:
                contract_depth[contract] = [int(depth)]
            else:
                with_callback = True
    
    return {"with_new_contract": with_new_contract, 
            "with_delegate_calls": with_delegate_calls, 
            "with_callback": with_callback, 
            "with_long_input": with_long_input, 
            "input_length": input_length}

def build_calltree_from_efg(efg):
    """
    Reconstruct a call tree from the EFG produced by the custom tracer.

    Important:
    - Each item in `efg` is an execution segment, not necessarily a whole call.
    - Segments at the same depth may belong to the same call instance and should be merged.
    """
    assert len(efg) > 0, "The execution flow graph (EFG) is empty."

    def _norm(val):
        """Normalize field values for identity comparison.
        The tracer may leave fields as None/undefined (e.g. precompile calls
        where opinfo.to and opinfo.input are never set), so treat those as "".
        """
        return "" if val is None else str(val)

    def make_call_node(seg, seg_idx):
        return {
            "contract": seg["contract"],
            "input": seg["input"],
            "call": seg["call"],
            "depth": seg["depth"],
            "value": seg.get("value"),
            "children": [],
            # "ops": list(seg["ops"]),
            "segments": [seg_idx],
        }

    # ---- root ----
    root_seg = efg[0]
    root_depth = root_seg["depth"]
    root = make_call_node(root_seg, 0)

    # active is keyed by *absolute depth*, so it works regardless of whether
    # the outermost call starts at depth 1 or any other value.
    active = {root_depth: root}

    for seg_idx, seg in enumerate(efg[1:], start=1):
        d = seg["depth"]

        if d < 1:
            raise ValueError(f"Unexpected depth {d} at segment {seg_idx}")

        # Case C: returned from deeper calls — discard any nodes deeper than d.
        for stale in [k for k in active if k > d]:
            del active[stale]

        if d in active:
            # Case B: resume the existing active call at this depth.
            curr = active[d]

            if _norm(curr["contract"]) != _norm(seg["contract"]) or \
               _norm(curr["call"])     != _norm(seg["call"])     or \
               _norm(curr["input"])    != _norm(seg["input"]):
                # Metadata mismatch at the same depth.  In a well-formed EFG
                # this shouldn't happen, but the tracer can leave None in
                # fields for precompile / edge-case calls.  Treat the segment
                # as a new sibling child of the parent rather than crashing.
                warnings.warn(
                    f"Segment metadata mismatch at depth {d}, seg_idx={seg_idx}: "
                    f"active=({curr['contract']}, {curr['call']}, {curr['input']!r}), "
                    f"seg=({seg['contract']}, {seg['call']}, {seg['input']!r}). "
                    "Treating as a new sibling call node."
                )
                if (d - 1) not in active:
                    raise ValueError(
                        f"Cannot attach mismatched segment at depth {d}: "
                        f"no parent node found at depth {d - 1}. seg_idx={seg_idx}"
                    )
                parent = active[d - 1]
                child = make_call_node(seg, seg_idx)
                parent["children"].append(child)
                active[d] = child
            else:
                # curr["ops"].extend(seg["ops"])
                curr["segments"].append(seg_idx)

        elif (d - 1) in active:
            # Case A: entering a new child call.
            parent = active[d - 1]
            child = make_call_node(seg, seg_idx)
            parent["children"].append(child)
            active[d] = child

        else:
            raise ValueError(
                f"Invalid depth transition at seg_idx={seg_idx}: "
                f"seg_depth={d}, active depths={sorted(active.keys())}"
            )

    return root

def locator(efg, 
            dump_trace_dir=None,  
            attc=None, 
            func=None, 
            idx=None, 
            wo_adv_contracts:bool=False, 
            wo_static:bool=True, 
            viscallgraph:bool=False):
    # ccep: callee-centric execution path — contract → {composite_input_key → [ops, ...]}
    ccep = get_callee_centric_execution_path(efg)
    # calltree: call tree built from the same EFG, used for scope expansion
    calltree = build_calltree_from_efg(efg)

    callee = attc or efg[0]['contract']

    if wo_adv_contracts:
        input = f"{efg[0]['depth']}_{efg[0]['call']}_{efg[0]['input']}_{int(efg[0].get('value', '0')) / 1e18}"
        traces = [(callee, input, [])]
        return attack_pattern(""), traces, calltree

    attack_scope, max_depth = expand_callees(callee, calltree)

    if viscallgraph:
        G = visualize_call_graph(
            graph=calltree,
            wo_static=wo_static,
            attack_scope=attack_scope,
            victim_scope=None,
            max_depth=max_depth + 1
        )
        graph_name = "dfs_cg"
        graph_name += "_wo_static" if wo_static else "_w_static"

        graph_path = f"{dump_trace_dir}/{graph_name}"

        G.render(graph_path, format='pdf', cleanup=True)
        print(f"Call graph saved to {graph_path}.pdf")

    if dump_trace_dir is not None:
        for contract, eps in ccep.items():
            input_map = {}
            for input_, eps in eps.items():
                input_map[input_] = len(input_map)
                instrument_dst_dir = f"{dump_trace_dir}/{contract}/input_{input_map[input_]}"
                os.makedirs(instrument_dst_dir, exist_ok=True)
                for i, ep in enumerate(eps):
                    dumps_trace(ep, f"{instrument_dst_dir}/trace_{i}.yaml")

            with open(f"{dump_trace_dir}/{contract}/input_map.json", "w") as f:
                json.dump(input_map, f, indent=4)

    # if callee is not None:
    #     # If idx is specified, we only analyze the specific trace for the callee.
    #     # sometimes, it is to debug.
    #     callee = callee.lower()
    #     assert callee in ccep, f"Callee {callee} not found in the execution path."
    #     callees = [(callee, _input) for _input in ccep[callee].keys()]

    # else:
    callees = attack_scope

    assert len(callees) > 0, f"No callees found for {callee} in the calltree."

    # to constrain our analysis scope
    # update the traces to dict, traces['callee_input'] = [trace1, trace2, ...]
    # duplicate traces are removed.
    recorded_traces = {}
    traces = []
    for callee, input in callees:
        assert input in ccep[callee], f"Input {input} not found for callee {callee} in the execution path."

        _, _call, _input, _value = input.split('_')
        if func is not None and not _input.startswith(func):
            continue

        _input = f"{_call}_{_input[:10]}_{_value}" # only need the function signature, ignore the parameters
        if _input not in recorded_traces:
            recorded_traces[_input] = set()

        for ops in ccep[callee][input]:
            if (h := hash_ops(ops)) is not None and h not in recorded_traces[_input]:
                recorded_traces[_input].add(h)
                traces.append((callee, input, ops))

    if idx is not None:
        assert idx < len(traces), f"Index {idx} out of range for callee {callee} with {len(traces)} traces."
        traces = [traces[idx]]

    return attack_pattern(attack_scope), traces, calltree
