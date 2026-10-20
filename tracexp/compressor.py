import time

import panoramix.settings as settings
from panoramix.prettify import explain, pprint_trace
from panoramix.simplify import if_to_require, require_to_if
from panoramix.utils.helpers import (C, get_concrete, get_hooked, get_pc,
                                     remove_hooked, opcode)
from tracexp.utils.helpers import decode_abi
from tracexp.utils.visualizer import visualize_cfg


def compressor(ir_list, to_require=True, _explain:bool=False):
    path_compressed = []
    max_loops = 1 # for metrics, count the max loops in the traces, which can reflect the compression effect to some extent
    for i, (callee, _input, trace) in enumerate(ir_list):
        depth, call, input, value = _input.split("_")
        if not call in ("CREATE", "CREATE2"):
            print(C.blue_back + f"Compressing trace: {callee}.{decode_abi(input[:10], input[10:])}" + C.end)
        else:
            print(C.blue_back + f"Compressing constructor trace: {callee}" + C.end)
        s = time.monotonic()
        _max_loops, c_ir = path_compressor(trace, to_require)
        max_loops = max(max_loops, _max_loops)
        path_compressed.append((callee, _input, c_ir))

        if _explain:
            explain("Compressed trace", c_ir, print_anyway=True)

        print(f"Compressing trace {i + 1}/{len(ir_list)} in {time.monotonic() - s:.2f} seconds")

    return max_loops, path_compressed


def path_compressor(trace, to_require=True):
    """
    Compress a while loop in the trace.
    """
    max_loops = 1
    if not trace:
        return max_loops, []
    
    if to_require:
        if settings.support_concrete:
            settings.support_concrete = False
            trace = if_to_require(trace)
            settings.support_concrete = True
        else:
            trace = if_to_require(trace)

    res = []
    idx = 0
    
    while idx < len(trace):
        line = trace[idx]
        pc = get_pc(line)
        
        if pc is None:
            res.append(line)
            idx += 1
            continue
        
        loop_info = detect_loop(trace, idx)
                
        if loop_info is None:
            res.append(line)
            idx += 1
        else:
            try:
                loop_body, body_length, iterations = loop_info
                
                if iterations > 1:
                    compressed_loop = summarize_loop(body_length, idx, iterations, trace)
                    res.extend(compressed_loop)
                    max_loops = max(max_loops, iterations)
                else:
                    res.extend(loop_body)
                
                idx += body_length * iterations
            except Exception as e:
                # raise e
                res.append(line)
                idx += 1
    if to_require:
        res = require_to_if(res)

    return max_loops, res

def detect_loop(trace, start_idx):
    """
    Try to detect a loop in the trace starting from start_idx.
    """
    if start_idx >= len(trace):
        return None

    # from pc aspects to detect loops
    # start_pc = get_pc(trace[start_idx])
    next_occurrences = find_next_occurrence(trace, start_idx)
    if next_occurrences is None or len(next_occurrences) == 0:
        return None
    
    for next_occurrence in next_occurrences:
        body_length = next_occurrence - start_idx
        if body_length <= 0:
            continue
        
        loop_body = trace[start_idx:start_idx + body_length]
        
        iterations = count_consistent_iterations(trace, start_idx, loop_body, body_length)
        
        if iterations > 5:
            return (loop_body, body_length, iterations)

    return None

def find_next_occurrence(trace, start_idx):
    """find the next occurrence after start_idx in the trace"""
    def get_meta(line):
        pc = get_pc(line)
        op = opcode(line)
        meta = None
        if op in ("call", "staticcall", "delegatecall", "callcode") and len(line) >= 3:
            meta = line[5] # called function
        return (pc, op, meta)
    target = get_meta(trace[start_idx])
    ocs = []
    for i in range(start_idx + 1, len(trace)):
        if get_meta(trace[i]) == target:
            ocs.append(i)
    return ocs

def count_consistent_iterations(trace, start_idx, loop_body, body_length):
    """
    Count how many times the loop_body appears in the trace starting from start_idx.
    """
    iterations = 0
    current_idx = start_idx
    
    while current_idx + body_length <= len(trace):
        current_segment = trace[current_idx:current_idx + body_length]
        
        if segments_equal(current_segment, loop_body):
            iterations += 1
            current_idx += body_length
        else:
            break
    
    return iterations

def segments_equal(segment1, segment2):
    """compare two segments of trace to see if they are equal based on their PC sequence."""
    if len(segment1) != len(segment2):
        return False
    
    for i in range(len(segment1)):
        if get_pc(segment1[i]) != get_pc(segment2[i]):
            return False
    
    return True

def summarize_loop(body_length, entry_idx, iterations, trace):
    """
    summarize a loop in the trace using a while loop structure.
    """
    loop_body = []
    for i in range(iterations):
        idx = entry_idx + i * body_length
        loop_body.append(trace[idx:idx + body_length])
    
    base_loop_body = loop_body[0]
    
    init_arrays = []
    all_step_changes = []
    
    for i in range(len(base_loop_body)):
        position_expressions = [remove_hooked(iteration[i]) for iteration in loop_body]
    
        step_change, arrays = analyze_position_with_arrays(position_expressions, 
                                                           array_idx=len(init_arrays))
        all_step_changes.append(step_change)
        
        if arrays:
            init_arrays.extend(arrays)
    
    changed_loop_body = []
    for i in range(len(base_loop_body)):
        if all_step_changes[i] is not None:
            new_line = apply_array_changes(base_loop_body[i], all_step_changes[i])
            changed_loop_body.append(new_line)
        else:
            changed_loop_body.append(base_loop_body[i])
    
    cond = ('lt', ('var', 0), iterations)
    init_vars = [('setvar', 0, 0)]
    continue_stmt = [('continue', '', (('setvar', 0, ('add', ('var', 0), 1)),))]
    
    loop_stmt = ('while', cond, changed_loop_body + continue_stmt, "", init_arrays + init_vars)
    
    try:
        if len(init_arrays) == 1 and len(init_arrays[0][-1]) > 2 and len(set(init_arrays[0][-1][:-1])) == 1 and init_arrays[0][-1][-1] != init_arrays[0][-1][-2]:
            new_loop_stmt = summarize_loop(body_length, entry_idx, iterations - 1, trace)
            
            return new_loop_stmt + [loop_body[-1]]
    except Exception as e:
        # raise e
        pass
    # TOFIX: the loops with dynamic return_data are not processed well
    # No semantic here, just skip them
    if any(opcode(s) in ("call", "delegatecall", "selfdestruct", "staticcall", "create", "create2") for s in changed_loop_body):
        return [loop_stmt]
    return []

def analyze_position_with_arrays(expressions, array_idx=0):
    """
    analyze the position changes in a list of expressions and determine if they can be represented
    using either a perfect arithmetic sequence or an array.
    
    Returns:
        (step_change, init_arrays)
    """
    if len(expressions) <= 1:
        return None, []
    
    if all(exp == expressions[0] for exp in expressions):
        return None, []
    
    path_differences = collect_path_differences(expressions)
    
    if not path_differences:
        return None, []
    
    final_patterns = {}
    init_arrays = []
    
    for path, value_sequence in path_differences.items():
        if is_perfect_arithmetic_sequence(value_sequence):
            pattern = create_arithmetic_pattern(value_sequence)
            final_patterns[path] = pattern
        else:
            array_name = ("var", f"a{array_idx}")
            array_type = infer_array_type(value_sequence)
            array_idx += 1
                        
            # change to setvar
            array_init = ('newmemarray', array_type, len(value_sequence), array_name, tuple(value_sequence))
            init_arrays.append(array_init)
            
            final_patterns[path] = {
                'type': 'array_access',
                'array_name': array_name
            }
    
    return final_patterns if final_patterns else None, init_arrays

def collect_path_differences(expressions):
    """
    collect differences in paths across a list of expressions.
    
    Returns:
        {path: [value0, value1, value2, ...], ...}
    """
    path_values = {}
    
    all_paths = set()
    for i in range(len(expressions) - 1):
        diff = diff_exp(expressions[i], expressions[i + 1])
        if diff:
            for path, _ in diff:
                all_paths.add(tuple(path))
    
    for path in all_paths:
        values = []
        for exp in expressions:
            value = get_value_at_path(exp, list(path))
            assert value is not None, f"Value at path {path} is None in expression {exp}"
            assert not type(value) in (tuple, list), f"Value at path {path} is a tuple in expression {exp}"
            values.append(value)
        
        if len(set(values)) > 1:
            path_values[path] = values
    
    return path_values

def is_perfect_arithmetic_sequence(values):
    """
    check if a list of values forms a perfect arithmetic sequence.
    """
    if len(values) < 2:
        return False
    
    if not all(isinstance(v, (int, float)) for v in values):
        return False
    
    differences = [values[i+1] - values[i] for i in range(len(values)-1)]
    
    return len(set(differences)) == 1

def create_arithmetic_pattern(values):
    """
    model a perfect arithmetic sequence pattern.
    """
    first_term = values[0]
    common_diff = values[1] - values[0]
    
    return {
        'type': 'arithmetic',
        'first_term': first_term,
        'common_diff': common_diff
    }

def infer_array_type(values):
    """
    type inference for array elements.
    """
    if not values:
        return 'any'
    
    types = set(type(v).__name__ for v in values)
    
    if len(types) == 1:
        type_name = list(types)[0]
        if type_name == 'int':
            return 'int'
        elif type_name == 'str':
            return 'string'

    return 'unknown_type'

def apply_array_changes(exp, patterns):
    """
    apply the changes to the expression based on the patterns detected.
    """
    import copy
    result = copy.deepcopy(exp)
    
    for path, pattern in patterns.items():
        if pattern['type'] == 'arithmetic':
            parameterized_value = create_arithmetic_expression(pattern)
        elif pattern['type'] == 'array_access':
            parameterized_value = ('marray', pattern['array_name'], ('var', 0))
        else:
            continue
        
        result = set_value_at_path(result, list(path), parameterized_value)
    
    return result

def create_arithmetic_expression(pattern):
    """
    create an arithmetic expression based on the pattern.
    """
    first_term = pattern['first_term']
    common_diff = pattern['common_diff']
    
    if common_diff == 0:
        return first_term
    elif common_diff == 1 and first_term == 0:
        return ('var', 0)
    elif common_diff == 1:
        return ('add', first_term, ('var', 0))
    elif first_term == 0:
        return ('mul', ('var', 0), common_diff)
    else:
        return ('add', first_term, ('mul', ('var', 0), common_diff))

def matched(exp1, exp2):
    if exp1 == exp2:
        return True
    else:
        return False
    # if opcode(exp1) == opcode(exp2) and opcode(exp1) in ("call", "delegatecall", "staticcall", "callcode"):
    #     return matched()
        
def diff_exp(exp1, exp2):
    if matched(exp1, exp2):
        return None
    
    differences = []
    _diff_exp_recursive(exp1, exp2, [], differences)
    return differences if differences else None

def _diff_exp_recursive(exp1, exp2, current_path, differences):
    if type(exp1) != type(exp2):
        differences.append((current_path.copy(), [exp1, exp2]))
        return
    
    if isinstance(exp1, tuple) and isinstance(exp2, tuple):
        if len(exp1) != len(exp2):
            differences.append((current_path.copy(), [exp1, exp2]))
            return
        for i in range(len(exp1)):
            _diff_exp_recursive(exp1[i], exp2[i], current_path + [i], differences)
    elif isinstance(exp1, list) and isinstance(exp2, list):
        if len(exp1) != len(exp2):
            differences.append((current_path.copy(), [exp1, exp2]))
            return
        for i in range(len(exp1)):
            _diff_exp_recursive(exp1[i], exp2[i], current_path + [i], differences)
    elif exp1 != exp2:
        differences.append((current_path.copy(), [exp1, exp2]))

def get_value_at_path(obj, path):
    current = obj
    for step in path:
        if isinstance(current, (tuple, list)) and step < len(current):
            current = current[step]
        else:
            return None
    return current

def set_value_at_path(obj, path, value):
    if not path:
        return value
    
    if isinstance(obj, tuple):
        obj_list = list(obj)
        if path[0] < len(obj_list):
            if len(path) == 1:
                obj_list[path[0]] = value
            else:
                obj_list[path[0]] = set_value_at_path(obj_list[path[0]], path[1:], value)
        return tuple(obj_list)
    elif isinstance(obj, list):
        if path[0] < len(obj):
            if len(path) == 1:
                obj[path[0]] = value
            else:
                obj[path[0]] = set_value_at_path(obj[path[0]], path[1:], value)
        return obj
    return obj