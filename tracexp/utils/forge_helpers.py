import json
import re
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .diff_utils import (get_call_info, locate_param_diff_flatten_line,
                         prettify_call_line)


class TraceType(Enum):
    CALL = "CALL"
    CREATE = "CREATE"
    CREATE2 = "CREATE2"
    SELFDESTRUCT = "SELFDESTRUCT"
    STATICCALL = "STATICCALL"
    DELEGATECALL = "DELEGATECALL"
    CALLCODE = "CALLCODE"

class TestStatus(Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"

class LineStatus(Enum):
    NORMAL = "NORMAL"
    ERROR = "ERROR"

@dataclass
class LogEntry:
    message: str
    status: LineStatus = LineStatus.NORMAL

@dataclass
class FlattenedResult:
    test_name: str
    test_func: str
    status: TestStatus
    logs: List[LogEntry]
    gas_used: Optional[int] = None
    
    flatten_calls: List[Tuple[str, int, str, str, str, str, str, str]] = None  # (status, depth, caller, contract, type, key, return_value, parent_key)
    creates_seq: List[str] = None
    new_addresses: Dict[str, str] = None
    
    # Attack analysis
    attack_successful: bool = False
    
    def __post_init__(self):
        if self.flatten_calls is None:
            self.flatten_calls = []
        if self.creates_seq is None:
            self.creates_seq = []
        if self.new_addresses is None:
            self.new_addresses = {}

class TraceParser:
    def __init__(self):
        # ANSI color code patterns
        self.ansi_patterns = {
            LineStatus.ERROR: re.compile(r'\[31m'),      # Red
        }
        self.ansi_cleanup = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        # Trace patterns
        self.call_pattern = re.compile(r'\[(\d+)\]\s+([^:]+)::([^(]+)\(([^)]*)\)')
        self.create_pattern = re.compile(r'\[(\d+)\]\s*→\s*new\s+([^@]+)@(0x[a-fA-F0-9]+)')
        self.selfdestruct_pattern = re.compile(r'\[(\d+)\]\s+selfdestruct\(([^)]*)\)')
        self.selfdestruct_contract_pattern = re.compile(r'\[(\d+)\]\s+([^:]+)::selfdestruct\(([^)]*)\)')
        
        self.call_with_type_pattern = re.compile(r'\[(\d+)\]\s+([^:]+)::([^(]+)\(([^)]*)\)\s+\[(staticcall|delegatecall|callcode)\]')
        self.address_call_with_type_pattern = re.compile(r'\[(\d+)\]\s+(0x[a-fA-F0-9]+)::([^(]+)\(([^)]*)\)\s+\[(staticcall|delegatecall|callcode)\]')
        
        self.address_call_pattern = re.compile(r'\[(\d+)\]\s+(0x[a-fA-F0-9]+)::([^(]+)\(([^)]*)\)')
        
        self.return_pattern = re.compile(r'└─ ← (.+)$')
        self.revert_pattern = re.compile(r'└─ ← revert:\s*(.+)$')
        
        # Attack analysis patterns
        self.before_pattern = re.compile(r'before attack: balance of ([^:]+):\s*([\d.]+)', re.IGNORECASE)
        self.after_pattern = re.compile(r'after attack: balance of ([^:]+):\s*([\d.]+)', re.IGNORECASE)

    def _detect_line_status(self, raw_line: str) -> LineStatus:
        for status, pattern in self.ansi_patterns.items():
            if pattern.search(raw_line):
                return status
        return LineStatus.NORMAL

    def _clean_ansi(self, line: str) -> str:
        return self.ansi_cleanup.sub('', line)

    def parse_foundry_output(self, file_path: str) -> List[FlattenedResult]:
        with open(file_path, 'r', encoding='utf-8') as f:
            raw_lines = f.readlines()
        
        processed_lines = []
        for raw_line in raw_lines:
            status = self._detect_line_status(raw_line)
            clean_line = self._clean_ansi(raw_line.rstrip('\n'))
            processed_lines.append((clean_line, status))
        
        test_sections = self._split_into_sections(processed_lines)
        
        results = []
        for section in test_sections:
            result = self._parse_single_test(section)
            if result:
                results.append(result)
        
        return results

    def _split_into_sections(self, processed_lines: List[Tuple[str, LineStatus]]) -> List[List[Tuple[str, LineStatus]]]:
        sections = []
        current_section = []
        
        for line, status in processed_lines:
            if re.match(r'Ran \d+ test for', line) and current_section:
                sections.append(current_section)
                current_section = [(line, status)]
            else:
                current_section.append((line, status))
        
        if current_section:
            sections.append(current_section)
        
        return sections

    def _parse_single_test(self, section: List[Tuple[str, LineStatus]]) -> Optional[FlattenedResult]:
        lines = [line for line, _ in section]
        
        test_name = self._extract_test_name(lines)
        if not test_name:
            return None
            
        test_func = self._extract_test_func(lines)
        status = self._extract_status(lines)
        gas_used = self._extract_gas_usage(lines)
        
        logs = self._extract_logs_with_status(section)
        
        trace_section = self._extract_trace_section(section)
        flatten_calls, creates_seq, new_addresses = self._parse_traces_to_flat(trace_section)
        
        attack_successful = self._analyze_attack_success(logs)
        
        result = FlattenedResult(
            test_name=test_name,
            test_func=test_func,
            status=TestStatus.PASSED if status == "PASSED" else 
                   TestStatus.FAILED if status == "FAILED" else TestStatus.UNKNOWN,
            logs=logs,
            gas_used=gas_used,
            flatten_calls=flatten_calls,
            creates_seq=creates_seq,
            new_addresses=new_addresses,
            attack_successful=attack_successful
        )
        
        return result

    def _extract_logs_with_status(self, section: List[Tuple[str, LineStatus]]) -> List[LogEntry]:
        logs = []
        in_logs = False
        
        for line, status in section:
            if line.strip() == 'Logs:':
                in_logs = True
                continue
            elif in_logs:
                if line.strip().startswith('Traces:') or not line.strip():
                    if line.strip().startswith('Traces:'):
                        break
                    continue
                logs.append(LogEntry(message=line.strip(), status=status))
        
        return logs

    def _extract_trace_section(self, section: List[Tuple[str, LineStatus]]) -> List[Tuple[str, LineStatus]]:
        trace_lines = []
        in_traces = False
        
        for line, status in section:
            if line.strip().startswith('Traces:'):
                in_traces = True
                continue
            elif in_traces and line.strip():
                trace_lines.append((line, status))
        
        return trace_lines

    def _parse_traces_to_flat(self, trace_section: List[Tuple[str, LineStatus]]) -> Tuple[List[Tuple[int, str, str, str, str]], List[str], Dict[str, str]]:
        flatten_calls = []
        creates_seq = []
        new_addresses = {}
        
        start_prank = False
        
        caller_stack = []
        
        call_return_mapping = self._build_call_return_mapping(trace_section)
        
        for i, (line, status) in enumerate(trace_section):
            depth = self._calculate_depth(line)

            if self._parse_return_value(line) is not None:
                caller_stack = [(d, c, k) for d, c, k in caller_stack if d < depth]
                continue

            trace_info = self._parse_trace_line(line)
            if not trace_info:
                continue

            trace_type, contract, function, params, created_addr = trace_info

            if contract == "VM" and function == "startPrank" and not "startPrank" in "\n".join(i[0] for i in trace_section[i+1:]):
                start_prank = True
                # continue

            # if not start_prank:
            #     continue

            caller, parent_key = self._get_caller_from_stack(caller_stack, depth)

            # key = f"{depth}_{trace_type}_{function}({params})"
            # key = f"{depth}_{trace_type}_0x"
            
            if function:
                # key = f"{contract}.{function}({params})"
                key = f"{depth}_{trace_type}_{contract}_{function}({params})"
            else:
                # key = f"{contract}.0x"
                key = f"{depth}_{trace_type}_{contract}_0x"

            if trace_type in ("CREATE", "CREATE2"):
                creates_seq.append(contract)
                if created_addr:
                    new_addresses[contract] = created_addr
                # caller_stack.append((depth, contract, key))
            elif start_prank and (trace_type in ("CALL", "DELEGATECALL", "STATICCALL", "CALLCODE", "SELFDESTRUCT")
                and contract != "VM" and "testPoC()" not in key):
                return_value = call_return_mapping.get(i, "")
                call_info = (status.value, depth, caller, contract, trace_type, key, return_value, parent_key)
                flatten_calls.append(call_info)

                if trace_type != "SELFDESTRUCT":
                    caller_stack.append((depth, contract, key))
        
        return flatten_calls, creates_seq, new_addresses

    def _get_caller_from_stack(self, caller_stack: List[Tuple[int, str, str]], current_depth: int) -> Tuple[str, str]:
        """Return (caller_contract, parent_key) for the call at current_depth.

        parent_key is the key of the caller's own call entry, giving context
        about which function in the caller contract triggered this call.
        """
        if not caller_stack:
            return "EOA", ""

        target_depth = current_depth - 1

        for depth, contract, key in reversed(caller_stack):
            if depth == target_depth:
                return contract, key

        last = caller_stack[-1]
        return last[1], last[2]

    def _build_call_return_mapping(self, trace_section: List[Tuple[str, LineStatus]]) -> Dict[int, str]:
        call_stack = []
        mapping = {}
        
        for i, (line, status) in enumerate(trace_section):
            depth = self._calculate_depth(line)
            
            return_value = self._parse_return_value(line)
            if return_value is not None:
                if call_stack:
                    for j in range(len(call_stack) - 1, -1, -1):
                        call_index, call_depth = call_stack[j]
                        if call_depth == depth - 1:
                            mapping[call_index] = return_value
                            call_stack.pop(j)
                            break
                continue
            
            trace_info = self._parse_trace_line(line)
            if trace_info:
                trace_type, contract, function, params, created_addr = trace_info
                if trace_type in ("CALL", "DELEGATECALL", "STATICCALL", "CALLCODE", "SELFDESTRUCT"):
                    call_stack.append((i, depth))
        
        return mapping

    def _parse_return_value(self, line: str) -> Optional[str]:
        revert_match = self.revert_pattern.search(line.strip())
        if revert_match:
            return f"revert: {revert_match.group(1).strip()}"
        
        return_match = self.return_pattern.search(line.strip())
        if return_match:
            return_value = return_match.group(1).strip()
            if not return_value.startswith('emit '):
                return return_value
        
        return None

    def _calculate_depth(self, line: str) -> int:
        line = line.strip(" ")
        depth = 0
        for char in line:
            if char in ['├', '└', '│', '┌', '┐', '┘', '┴', '┬', '┼']:
                depth += 4
        return depth // 4

    def _parse_trace_line(self, line: str) -> Optional[Tuple[str, str, str, str, str]]:
        # CREATE
        create_match = self.create_pattern.search(line)
        if create_match:
            contract = create_match.group(2).strip()
            addr = create_match.group(3)
            return ("CREATE", contract, None, "", addr)
        
        # SELFDESTRUCT with contract
        selfdestruct_contract_match = self.selfdestruct_contract_pattern.search(line)
        if selfdestruct_contract_match:
            contract = selfdestruct_contract_match.group(2).strip()
            beneficiary = selfdestruct_contract_match.group(3).strip()
            return ("SELFDESTRUCT", contract, "selfdestruct", beneficiary, "")
        
        # SELFDESTRUCT
        selfdestruct_match = self.selfdestruct_pattern.search(line)
        if selfdestruct_match:
            beneficiary = selfdestruct_match.group(2).strip()
            return ("SELFDESTRUCT", "", "selfdestruct", beneficiary, "")
        
        # (contract::function() [calltype])
        call_with_type_match = self.call_with_type_pattern.search(line)
        if call_with_type_match:
            contract = call_with_type_match.group(2).strip()
            function = call_with_type_match.group(3).strip()
            params = call_with_type_match.group(4).strip()
            call_type = call_with_type_match.group(5).upper()
            return (call_type, contract, function, params, "")
        
        # (0x...::function() [calltype])
        address_call_with_type_match = self.address_call_with_type_pattern.search(line)
        if address_call_with_type_match:
            address = address_call_with_type_match.group(2)
            function = address_call_with_type_match.group(3).strip()
            params = address_call_with_type_match.group(4).strip()
            call_type = address_call_with_type_match.group(5).upper()
            return (call_type, address, function, params, "")
        
        # default CALL with address
        address_call_match = self.address_call_pattern.search(line)
        if address_call_match:
            address = address_call_match.group(2)
            function = address_call_match.group(3).strip()
            params = address_call_match.group(4).strip()
            return ("CALL", address, function, params, "")
        
        # default CALL
        call_match = self.call_pattern.search(line)
        if call_match:
            contract = call_match.group(2).strip()
            function = call_match.group(3).strip()
            params = call_match.group(4).strip()
            return ("CALL", contract, function, params, "")
        
        return None

    def _analyze_attack_success(self, logs: List[LogEntry]) -> bool:
        before_balances = {'address(attC)': Decimal(0)}
        after_balances = {}
        
        for log in logs:
            message = log.message
            
            before_match = self.before_pattern.search(message)
            if before_match:
                account = before_match.group(1).strip()
                balance = Decimal(before_match.group(2))
                before_balances[account] = balance
                continue
            
            after_match = self.after_pattern.search(message)
            if after_match:
                account = after_match.group(1).strip()
                balance = Decimal(after_match.group(2))
                after_balances[account] = balance
        
        for account in before_balances:
            if account in after_balances:
                profit = after_balances[account] - before_balances[account]
                if profit > 0: 
                    return True
        
        return False

    def _extract_test_name(self, lines: List[str]) -> Optional[str]:
        for line in lines:
            if 'Ran' in line and 'test for' in line:
                return line.split('test for ')[-1].strip()
        return None

    def _extract_test_func(self, lines: List[str]) -> Optional[str]:
        # for line in lines:
        #     if '[PASS]' in line or '[FAIL]' in line:
        #         parts = line.split(' ')
        #         for i, part in enumerate(parts):
        #             if part in ['[PASS]', '[FAIL]'] and i + 1 < len(parts):
        #                 return parts[i + 1]
        for line in lines:
            match = re.search(r'\[(PASS|FAIL(?:\.[^]]*)?)\]\s+(\w+)\s*\(', line)
            if match:
                return match.group(2)
        return None

    def _extract_status(self, lines: List[str]) -> str:
        for line in lines:
            if '[PASS' in line:
                return "PASSED"
            elif '[FAIL' in line:
                return "FAILED"
        return "UNKNOWN"

    def _extract_gas_usage(self, lines: List[str]) -> Optional[int]:
        for line in lines:
            match = re.search(r'\(gas: (\d+)\)', line)
            if match:
                return int(match.group(1))
        return None

def flatten_call_trace(root_trace: Dict, _receiver=None, _input=None, max_calllen=-1) -> Dict[str, Dict]:
    if _receiver is None:
        _receiver = list(root_trace.keys())[0]
    if _input is None:
        _input = list(root_trace[_receiver].keys())[0]
    
    receiver = _receiver
    
    flatten_call_result = []
    creates_seq = []
    
    def process_trace(_sender, _receiver, _input):
        if "CREATE" in _input:
            creates_seq.append(_receiver)
        else:
            if "DELEGATECALL" in _input and _receiver not in creates_seq and _sender in creates_seq:
                creates_seq.append(_receiver)
            try:
                depth, __type, __input, _value = _input.split("_", 3)
            except:
                depth, __type, __input = _input.split("_", 2)
                _value = 0
            call_info = (
                depth,
                _sender,
                _receiver,
                __type,
                _input
            )
            flatten_call_result.append(call_info)
            if max_calllen != -1 and len(flatten_call_result) >= max_calllen:
                return
        for depth, rec, call, inp in root_trace.get(_receiver, {}).get(_input, []):
            process_trace(_receiver, rec, inp)

    process_trace("EOA", _receiver, _input)
    
    return flatten_call_result, creates_seq, receiver

def flatten_call_trace_from_tree(calltree, max_calllen=-1):
    """
    Flatten call tree into a linear call sequence (preorder traversal).

    Returns:
        flatten_call_result: List of (depth, sender, receiver, call_type, input)
        creates_seq: List of created contract addresses
        receiver: root contract
    """

    flatten_call_result = []
    creates_seq = []

    def dfs(node, parent_contract):
        nonlocal flatten_call_result, creates_seq

        call_type = node.get("call", "")
        receiver = node.get("contract")
        input_data = node.get("input")
        depth = node.get("depth")
        value = node.get("value", "0")
        if value is not None:
            value = int(value) / 1e18
        else:
            value = 0.0
        _input = f"{depth}_{call_type}_{input_data}_{value}"

        if "CREATE" in call_type:
            creates_seq.append(receiver)

        else:
            if "DELEGATECALL" in call_type and receiver not in creates_seq and parent_contract in creates_seq:
                creates_seq.append(receiver)

            call_info = (
                depth,
                parent_contract,
                receiver,
                call_type,
                _input,
            )

            flatten_call_result.append(call_info)

            if max_calllen != -1 and len(flatten_call_result) >= max_calllen:
                return

        for child in node.get("children", []):
            dfs(child, receiver)

    dfs(calltree, "EOA")

    receiver = calltree.get("contract")

    return flatten_call_result, creates_seq, receiver

def debug_print_flattened(creates_seq, forge_creates_seq, forge_new_addresses, flattened, is_forge=False):
    lines = []
    for line in flattened:
        lines.append(prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, line, is_forge=is_forge))
    
    return "\n".join(lines)

def _fmt_diff(reason: str, observed: list[str], expected: list[str]) -> str:
    lines = [f"@@ {reason} @@"]
    for l in observed:
        lines.append(f"observed: {l}")
    for l in expected:
        lines.append(f"expected: {l}")
    return "\n".join(lines)


def calltrace_diff(callgraph, ref_callgraph, is_debug=False):
    diffs = []
    forge_flattened, forge_creates_seq, forge_new_addresses = (
        callgraph.flatten_calls,
        callgraph.creates_seq,
        callgraph.new_addresses,
    )
    flattened, creates_seq, receiver = flatten_call_trace_from_tree(
        ref_callgraph, max_calllen=len(forge_flattened) + 25
    )

    if len(creates_seq) == 0 or receiver != creates_seq[0]:
        creates_seq = [receiver] + creates_seq

    if is_debug:
        lines_forge = debug_print_flattened(
            creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened, is_forge=True
        )
        lines_ref = debug_print_flattened(
            creates_seq, forge_creates_seq, forge_new_addresses, flattened, is_forge=False
        )
        with open("forge_flattened.txt", "w") as f:
            f.write(lines_forge)
        with open("ref_flattened.txt", "w") as f:
            f.write(lines_ref)
        return

    # Execution errors
    has_error = any(s[0] == "ERROR" for s in forge_flattened)

    if has_error:
        observed_any = False
        unmatched = []
        error_context = None

        for s in range(len(forge_flattened)):
            current_forge_line = forge_flattened[s]
            status = current_forge_line[0]
            _, forge_caller, forge_callee, *_, context = get_call_info(
                creates_seq, forge_creates_seq, forge_new_addresses, current_forge_line, is_foundry=True
            )
            # if context.startswith("AttackerC"):
            error_context = context

            if status == "ERROR" and (forge_caller in forge_new_addresses or forge_callee in forge_new_addresses):
                synth_str = prettify_call_line(
                    creates_seq, forge_creates_seq, forge_new_addresses, current_forge_line, is_forge=True
                )
                fl = locate_param_diff_flatten_line(
                    forge_flattened[s], s, flattened, creates_seq, forge_creates_seq, forge_new_addresses
                )
                if fl is not None:
                    observed_any = True
                    ref_str = prettify_call_line(
                        creates_seq, forge_creates_seq, forge_new_addresses, fl, is_forge=False
                    )
                    diffs.append(_fmt_diff("execution error", [synth_str], [ref_str]))
                else:
                    unmatched.append(synth_str)
                    
            if not any(l[0] == "ERROR" for l in forge_flattened[s + 1:]):
                break

        if error_context is not None:
            diffs.append(f"@@ execution errors in context: {error_context} @@")
        else:
            diffs.append(f"@@ execution errors (no matching reference) @@")
        diffs.extend(f"{e}" for e in unmatched)

        if observed_any:
            return "\n".join(diffs)

    # Call-sequence differences
    seq_diffs = []

    for s in range(max(len(flattened), len(forge_flattened))):
        if s >= len(flattened) or s >= len(forge_flattened):
            n_exp, n_got = len(flattened), len(forge_flattened)
            block = [f"@@ trace length mismatch: expected {n_exp}, got {n_got} @@"]
            if s >= len(forge_flattened):
                lasts = []
                for i in range(max(0, s - 5), s):
                    lasts.append(prettify_call_line(
                        creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened[i], is_forge=True
                    ))
                
                nexts = []
                for i in range(s, min(s + 5, len(flattened))):
                    nexts.append(prettify_call_line(
                        creates_seq, forge_creates_seq, forge_new_addresses, flattened[i], is_forge=False
                    ))               
                    
                # print the last 5 lines of Foundry output
                stop_flag = "stop" if not has_error else "revert"
                block.append(f"Last execution lines before {stop_flag}:")
                if len(lasts) > 0:
                    block.append("\n".join(lasts))
                
                block.append(f"Next reference execution lines:")
                if len(nexts) > 0:
                    block.append("\n".join(nexts))
            seq_diffs.append("\n".join(block))
            break

        current_forge_line = forge_flattened[s]
        current_line = flattened[s]

        forge_depth, forge_caller, forge_callee, forge_func, forge_params, *_ = get_call_info(
            creates_seq, forge_creates_seq, forge_new_addresses, current_forge_line, is_foundry=True
        )
        depth, caller, callee, func, params, *_ = get_call_info(
            creates_seq, forge_creates_seq, forge_new_addresses, current_line, is_foundry=False
        )

        if forge_caller not in forge_new_addresses:
            continue

        if forge_depth != depth:
            reason, context_len = "different call sequences", 3
        elif forge_callee != callee:
            reason, context_len = "different callee", 1
        elif forge_func != func:
            reason, context_len = "different function called", 1
        elif forge_params != params:
            if len(forge_params) == len(params):
                bad = [str(i) for i in range(len(forge_params)) if forge_params[i] != params[i]]
                reason = "different parameters at position " + ", ".join(bad)
            else:
                reason = "different parameters"
            context_len = 1
        else:
            continue

        lo = max(0, s - context_len // 2)
        hi = min(s + context_len // 2 + 1, len(forge_flattened))

        ob_exec, re_exec = [], []
        for j in range(lo, hi):
            ob_exec.append(prettify_call_line(
                creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened[j]
            ))
            fl = locate_param_diff_flatten_line(
                forge_flattened[j], j, flattened, creates_seq, forge_creates_seq, forge_new_addresses
            )
            if fl is not None:
                re_exec.append(prettify_call_line(
                    creates_seq, forge_creates_seq, forge_new_addresses, fl, is_forge=False
                ))

        seq_diffs.append(_fmt_diff(reason, ob_exec, re_exec))

    if not seq_diffs:
        return "\n".join(diffs) if diffs else ""

    return "\n".join(diffs) + "\nThe partial different executions from bottom to up are:\n" + "\n".join(reversed(seq_diffs))

# def calltrace_diff(callgraph, ref_callgraph, is_debug=False):
#     """Compare the call traces of the synthesized code with the original trace."""
#     diffs = []
#     forge_flattened, forge_creates_seq, forge_new_addresses = callgraph.flatten_calls, callgraph.creates_seq, callgraph.new_addresses
#     flattened, creates_seq, receiver = flatten_call_trace_from_tree(ref_callgraph, max_calllen=len(forge_flattened)+25)
            
#     if len(creates_seq) == 0 or receiver != creates_seq[0]:
#         creates_seq = [receiver] + creates_seq
    
#     if is_debug:
#         lines_forge = debug_print_flattened(creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened, is_forge=True)
#         lines_ref = debug_print_flattened(creates_seq, forge_creates_seq, forge_new_addresses, flattened, is_forge=False)
        
#         with open("forge_flattened.txt", "w") as f:
#             f.write(lines_forge)
            
#         with open("ref_flattened.txt", "w") as f:
#             f.write(lines_ref)

#         return
        
#     has_error = any(s[0] == "ERROR" for s in forge_flattened)
    
#     if has_error:
#         observed = False
#         errors_messages = []
#         for s in range(len(forge_flattened)):
#             current_forge_line = forge_flattened[s]
            
#             status = current_forge_line[0]
#             forge_depth, forge_caller, forge_callee, forge_func, forge_params, forge_ret = get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, current_forge_line, is_foundry=True)

#             if status == "ERROR" and forge_caller in forge_new_addresses:
#                 if (fl:=locate_param_diff_flatten_line(forge_flattened[s], s, flattened, creates_seq, forge_creates_seq, forge_new_addresses)) is not None:
#                     observed = True
#                     diffs.append(f"Execution error at the call {prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened[s], is_forge=True)}")
#                     diffs.append(f"But observed {prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, fl, is_forge=False)} \n")        
#                 else:
#                     errors_messages.append(f"{prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened[s], is_forge=True)}")
#             if not any(l[0] == "ERROR" for l in forge_flattened[s+1:]):
#                 break
#         if observed:
#             return "\n".join(diffs)
#         else:
#             diffs.append("We observed execution errors in the execution trace: "+ "\n\t".join(errors_messages))

#     seq_diffs = []

#     for s in range(max(len(flattened), len(forge_flattened))):
#         if s >= len(flattened) or s >= len(forge_flattened):
#             seq_diffs.append(f"The lengths of the call traces are different, expected {len(flattened)} calls but got {len(forge_flattened)} calls.")
#             if s >= len(forge_flattened):
#                 seq_diffs.append(f"The last error call of the synthesized code is: \n" + prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened[-1], is_forge=True))
#                 seq_diffs.append("the next line may have errors")
#                 seq_diffs.append(f"There are still some observed executions not covered by the synthesized code, such as the next line is: \n" + prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, flattened[s], is_forge=False))
#             break
#         current_line = flattened[s]
#         current_forge_line = forge_flattened[s]
        
#         status = current_forge_line[0]
#         forge_depth, forge_caller, forge_callee, forge_func, forge_params, forge_ret = get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, current_forge_line, is_foundry=True)
#         depth, caller, callee, func, params, ret = get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, current_line, is_foundry=False)
                
#         reason = ""
#         if forge_caller not in forge_new_addresses:
#             continue
        
#         if forge_depth != depth:
#             reason = "different call sequences"
#             context_len = 3        
                    
#         elif forge_callee != callee:
#             reason = "different callee"
#             context_len = 1
            
#         elif forge_func != func:
#             reason = "different function called"
#             context_len = 1
            
#         elif forge_params != params and forge_caller in forge_new_addresses:
#             reason = "different parameters"
#             if len(forge_params) == len(params):
#                 diffsi = []
#                 for i in range(len(forge_params)):
#                     if forge_params[i] != params[i]:
#                         diffsi.append(i)
#                 reason += " at position " + ", \n\t".join(str(i) for i in diffsi)
#             context_len = 1
        
#         else: 
#             continue
        
#         ob_exec = []
#         re_exec = []
        
#         for j in range(max(0, s - context_len // 2), min(s + context_len // 2 + 1, len(forge_flattened))):
#             ob_exec.append(prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, forge_flattened[j]))
#             if (fl:=locate_param_diff_flatten_line(forge_flattened[j], j, flattened, creates_seq, forge_creates_seq, forge_new_addresses)) is not None:
#                 re_exec.append(prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, fl, is_forge=False))

#         if len(re_exec) > 0:
#             seq_diffs.append(f"Observed execution with {reason}:" + '\n\t '.join(ob_exec) + "\nBut expected:" + '\n\t '.join(re_exec))
#         else:
#             seq_diffs.append(f"Observed execution with {reason}:" + '\n\t '.join(ob_exec))

#     return "\n".join(diffs) + "\nThe differences from bottom to up are:\n" + "\n".join(reversed(seq_diffs))