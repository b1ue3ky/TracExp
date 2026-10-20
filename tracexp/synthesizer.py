from collections import defaultdict

import panoramix.settings as settings
from panoramix.prettify import explain, pprint_trace, trace_to_str
from panoramix.rewriter import rewrite_call_args
from panoramix.simplify import cleanup_conds
from panoramix.utils.helpers import (Any, cached, find_f_set, get_concrete,
                                     get_hooked, match, opcode, replace_f,
                                     rewrite_trace_full, rewrite_trace_ifs,
                                     to_checksum_address)
from tracexp.compressor import path_compressor
from tracexp.prompt import (CALL_IDENTITY_EXAMPLES, synthesis_sys_prompt,
                        synthesis_user_prompt)
from tracexp.utils import (ADD_TYPE, LLM, decode_abi, extract_code_from_content,
                       get_allowance, get_blocktimestamp, get_contract_abi,
                       get_contract_name, get_existing_interfaces,
                       get_func_interface, get_func_name, is_erc20,
                       make_prompt, make_request, only_decode,
                       write_code_to_file)

wo_adv_poc_templates = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "../interface.sol";

{involved_addrs}

contract ContractTest is Test {{
    function setUp() public {{
        vm.createSelectFork(\"{chain}\", {blocknumber}-1);{deals}
    }}
    
    function testPoC() public {{
{pre_attack_logs}
        vm.startPrank(attacker, attacker);{attack_calls}
        vm.stopPrank();
{post_attack_logs}
    }}
}}

{involved_abis}
"""

poc_template = """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";
import "../interface.sol";

{involved_addrs}

contract ContractTest is Test {{
    function setUp() public {{
        vm.createSelectFork(\"{chain}\", {blocknumber}-1);{deals}
    }}
    {setup_approves}
    function testPoC() public {{
{pre_attack_logs}
        vm.startPrank(attacker, attacker);
        AttackerC attC = new AttackerC{init_value}();{attack_deals}{attack_approves}{attack_calls}
        vm.stopPrank();
{post_attack_logs}
    }}
}}

// {attack_contract}
contract AttackerC {{
{attack_functions}
  
    // <PLACEHOLDER> other functions
}}

// <PLACEHOLDER> other contracts

{involved_abis}
"""

IDENT = "    "

CHAINS = {
    "eth": "mainnet",
    "bsc": "bsc",
}

@cached
def find_addr(exp):
    def f(exp):
        if type(exp) == int and exp > 8**50:
            hex_exp = hex(exp)
            if len(hex_exp) > 17*2+2 and len(hex_exp) <= 20*2+2: # change to constant address to checksums
                return set([to_checksum_address(hex_exp)])
            
        elif type(exp) == str and exp.startswith("0x") and len(exp) >=18 *2 and len(exp) <= 40 + 2:
            return set([to_checksum_address(exp)])

        return set()
    
    return find_f_set(exp, f)

@cached
def find_fun(exp):
    def f(exp):
        if opcode(exp) in ("call", "callcode", "delegatecall", "staticcall"):
            addr, fname = exp[3], exp[5]
            if addr is None or fname is None:
                return set()
            if isinstance(addr, tuple):
                addr = get_concrete(addr)
            
            if isinstance(addr, int):
                addr = to_checksum_address(hex(addr))
            
            if not type(addr) == str or not addr.startswith("0x") or len(addr) != 42:
                return set()
            
            if isinstance(fname, tuple):
                fname = get_concrete(fname)
            if isinstance(fname, int):
                fname = '0x' + hex(fname)[2:].rjust(8, '0')
            return set([(addr, fname)])
    
        else:
            return set()
    
    return find_f_set(exp, f)

Ic = 0
def transferInterface(name, existing_interfaces):
    global Ic
    if not f"I{name}" in existing_interfaces:
        return f"I{name}"
    elif not f"I{name.lower()}" in existing_interfaces:
        return f"I{name.lower()}"
    elif not f"ABI{name}" in existing_interfaces:
        return f"ABI{name}"
    elif not f"ABI{name.lower()}" in existing_interfaces:
        return f"ABI{name.lower()}"
    else:
        Ic += 1
        return f"I{name}{Ic}"

def get_involved_funcs(attacker, receiver, chain, _irs, wo_adv_contracts):
    involved_addrs = ""
    involved_abis = ""
    addrs = find_addr(_irs) | set([attacker])
    contract_addrs = set()
    contracts = {}
    contract_names = {}
    if wo_adv_contracts:
        for irs in _irs:
            for addr, _input, ir in irs:
                addr = to_checksum_address(addr)
                if addr not in contracts:
                    contracts[addr] = set()
                _, call, intput_, value_ = _input.split("_")
                if call not in ("CREATE", "CREATE2"):
                    name = get_func_name(intput_[:10])
                    if not name.startswith("unknown"):
                        contracts[addr].add(intput_[:10])
    else:
        for irs in _irs:
            for addr, _input, ir in irs:
                funcs = find_fun(ir)
                if funcs:
                    for c, f in funcs:
                        if to_checksum_address(c) == to_checksum_address(receiver):
                            continue
                        
                        if c not in contracts:
                            contracts[to_checksum_address(c)] = set()
                        contracts[to_checksum_address(c)].add(f)

    existing_interfaces = get_existing_interfaces()
    involved = []
    const_addrs = []
    for c, funcs in contracts.items():
        name = get_contract_name(chain, c)
        if name is not None and len(name) > 0:
            contract_names[to_checksum_address(c)] = name
            cname = name
            if cname in existing_interfaces:
                cname = cname.lower()
            if (t:= const_addrs.count(cname)) >= 1:
                cname += f"{t + 1}"
            const_addrs.append(name)
            involved_addrs += f"address constant {cname} = {to_checksum_address(c)};\n"
            contract_addrs.add(to_checksum_address(c))
            
            if (Iname:=transferInterface(name, existing_interfaces)) is not None:
                abis = []
                for f in funcs:
                    abi = get_func_interface(chain, c, f)
                    if abi:
                        abis.append(abi)
                if len(abis) > 0:
                    # involved_abis.append((f"I{name}", abis))
                    involved_abis += f"interface {Iname}" + " {\n" + '\n'.join(abis) + " \n}\n"
                    involved.append(f"{Iname}")
            
            # involved_addrs.append((name, to_checksum_address(c)))
            # if f"I{name}" not in existing_interfaces:
            #     abis = []
            #     for f in funcs:
            #         abi = get_func_interface(chain, c, f)
            #         if abi:
            #             abis.append(abi)
            #     if len(abis) > 0:
            #         # involved_abis.append((f"I{name}", abis))
            #         involved_abis += f"interface I{name}" + " {\n" + '\n'.join(abis) + " \n}\n"
            #         involved.append(f"I{name}")
            #     # else:
            #     #     involved_abis += f"interface {name}" + "{\n <PLACEHOLDER> \n}\n"
            # elif f"I{name}" not in involved: # we decide to keep the interface for providing more semantics
            #     involved_abis += f"// interface I{name} has been already declared in the interface.sol \n"
            #     involved.append(f"I{name}")
                
    unknown_addrs = set()
    i = 1
    for addr in addrs - contract_addrs:
        if to_checksum_address(addr) == to_checksum_address(attacker):
            name = "attacker"
            involved_addrs += f"address constant {name} = {addr};\n"
        elif to_checksum_address(addr) != to_checksum_address(receiver):
            name = f"addr{i}"
            unknown_addrs.add(name)
            i += 1
            involved_addrs += f"address constant {name} = {addr};\n"

    return contract_names, involved_addrs, involved_abis, unknown_addrs

def synthesizer_oracles(chain, oraclers, attacker, receiver, blocknumbers, tx_inputs="", callgraph=None):
    # synthesizer_deals -> attacker deals, attack contract deals
    # synthesizer_logs -> before attack logs, after attack logs
    # synthesizer_approves -> pre attack allowances
    deals = synthesizer_deals(oraclers, attacker, who="attacker")
    attack_deals = synthesizer_deals(oraclers, receiver, who="address(attC)")
    pre_attack_logs, post_attack_logs = "", ""
    flow_changes, pre_attack_logs, post_attack_logs = synthesizer_logs(oraclers, attacker, benificiary_tag="attacker")
    if len(pre_attack_logs) == 0 and len(post_attack_logs) == 0:
        _, pre_attack_logs, post_attack_logs = synthesizer_logs(oraclers, receiver, benificiary_tag="address(attC)", flow_changes=flow_changes)
        if len(pre_attack_logs) == 0 and len(post_attack_logs) == 0 and len(tx_inputs) > 2:
            for addr in flow_changes:
                if addr[2:].lower() in tx_inputs[2:].lower() and int(addr, 16) != 0:
                    for token in flow_changes[addr]:
                        if flow_changes[addr][token] > 0:
                            _, pre_attack_logs, post_attack_logs = synthesizer_logs(oraclers, addr, benificiary_tag=f"address({to_checksum_address(addr)})", flow_changes=flow_changes)
                            break
        
        if len(pre_attack_logs) == 0 and len(post_attack_logs) == 0:
            # find the max flow_changes
            max_value = -1
            max_addr = None
            for addr in flow_changes:
                if int(addr, 16) == 0:
                    continue
                for token in flow_changes[addr]:
                    if flow_changes[addr][token] > 0 and flow_changes[addr][token] > max_value:
                        max_value = flow_changes[addr][token]
                        max_addr = addr
                        
            if max_addr is not None:
                _, pre_attack_logs, post_attack_logs = synthesizer_logs(oraclers, max_addr, benificiary_tag=f"address({to_checksum_address(max_addr)})", flow_changes=flow_changes)
        
    # setup_approves, approves = synthesizer_approves(receiver, root_call, callgraph, root_caller=attacker)
    setup_approves, approves = synthesizer_approves_from_tree(chain, receiver, callgraph)
    return deals, attack_deals, pre_attack_logs, post_attack_logs, setup_approves, approves

def parse_call_key(call_key):
    parts = call_key.split("_", 3)
    if len(parts) < 3:
        return None
    try:
        depth = int(parts[0])
    except:
        depth = 0
    calltype = parts[1]
    data = parts[2]
    selector = data[:10].lower() if len(data) >= 10 else None
    return depth, calltype, data, selector

def decode_transfer_from(data):
    try:
        raw = bytes.fromhex(data[10:])
        owner, to, amount = only_decode(
            ["address", "address", "uint256"], raw
        )
        return owner.lower(), to.lower(), int(amount)
    except:
        return None


def decode_approve(data):
    try:
        raw = bytes.fromhex(data[10:])
        spender, amount = only_decode(
            ["address", "uint256"], raw
        )
        return spender.lower(), int(amount)
    except:
        return None

def synthesizer_approves_from_tree(chain, receiver, calltree):
    TRANSFERFROM_SELECTOR = "0x23b872dd"
    APPROVE_SELECTOR = "0x095ea7b3"
    
    events = []
    order_counter = [0]

    def dfs(node, current_contract, msg_sender):
        """
        node: current call node
        current_contract: address(this)
        msg_sender: msg.sender
        """

        call_type = node.get("call", "")
        data = node.get("input", "")
        contract = node.get("contract", "").lower()

        # ---- decode selector ----
        selector = None
        if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
            selector = data[:10]

        is_erc20_token = is_erc20(chain, contract)
        
        if is_erc20_token:
            # ---- transferFrom ----
            if selector == TRANSFERFROM_SELECTOR:
                decoded = decode_transfer_from(data)
                if decoded:
                    owner, to, amount = decoded

                    events.append({
                        "type": "transferFrom",
                        "token": contract,
                        "owner": owner.lower(),
                        "spender": msg_sender.lower(),
                        "amount": amount,
                        "order": order_counter[0],
                    })
                    order_counter[0] += 1

            # ---- approve ----
            elif selector == APPROVE_SELECTOR:
                decoded = decode_approve(data)
                if decoded:
                    spender_, amount = decoded

                    events.append({
                        "type": "approve",
                        "token": contract,
                        "owner": msg_sender.lower(),
                        "spender": spender_.lower(),
                        "amount": amount,
                        "order": order_counter[0],
                    })
                    order_counter[0] += 1

        # Traverse child calls.
        for child in node.get("children", []):
            child_type = child.get("call", "")

            if child_type == "DELEGATECALL":
                # address(this) and msg.sender are unchanged.
                dfs(child, current_contract, msg_sender)

            else:
                # CALL / STATICCALL
                dfs(child, child.get("contract", "").lower(), current_contract)

    # Root: EOA -> first contract.
    root_contract = calltree.get("contract", "").lower()
    dfs(calltree, root_contract, "EOA")

    # Analyze allowances.
    allowance = defaultdict(int)
    lacking = set()

    for e in sorted(events, key=lambda x: x["order"]):
        token = e["token"]
        owner = e["owner"]
        spender = e["spender"]
        key = (token, owner, spender)

        if e["type"] == "approve":
            allowance[key] = e["amount"]

        elif e["type"] == "transferFrom":
            if allowance[key] >= e["amount"]:
                allowance[key] -= e["amount"]
            else:
                lacking.add(key)
                allowance[key] = 0

    results = []

    for token, owner, spender in lacking:
        if owner != receiver.lower() and spender != receiver.lower():
            continue
        results.append({
            "token": token,
            "owner": owner,
            "spender": spender,
            "amount": "type(uint256).max"
        })

    # return results, events
    func_name = "setupApprovals"
    
    return generate_foundry_approve_function(results, receiver, func_name), f"\n\t{func_name}(address(attC));" if len(results) > 0 else ""

# def synthesizer_approves(receiver, root_call, callgraph, root_caller=None):
#     TRANSFERFROM_SELECTOR = "0x23b872dd"
#     APPROVE_SELECTOR = "0x095ea7b3"

#     receiver = receiver.lower()
#     root_caller = (root_caller or receiver).lower()

#     events = []
#     visited = set()
#     order_counter = [0]

#     def dfs(contract, call_key, msg_sender):
#         # contract = address(this), the currently executing contract
#         # msg_sender = msg.sender, the caller of the current contract
#         contract = contract.lower()
#         msg_sender = msg_sender.lower()

#         state = (contract, call_key, msg_sender)
#         if state in visited:
#             return
#         visited.add(state)

#         parsed = parse_call_key(call_key)
#         if parsed:
#             _, calltype, data, selector = parsed

#             if selector == TRANSFERFROM_SELECTOR:
#                 decoded = decode_transfer_from(data)
#                 if decoded:
#                     owner, to, amount = decoded
#                     # spender is the caller of transferFrom, that is msg.sender of this call
#                     spender = msg_sender

#                     events.append({
#                         "type": "transferFrom",
#                         "token": contract,
#                         "owner": owner,
#                         "spender": spender,
#                         "amount": amount,
#                         "order": order_counter[0],
#                     })
#                     order_counter[0] += 1

#             elif selector == APPROVE_SELECTOR:
#                 decoded = decode_approve(data)
#                 if decoded:
#                     spender_, amount = decoded
#                     # owner is the caller of approve, that is msg.sender of this call
#                     owner = msg_sender

#                     events.append({
#                         "type": "approve",
#                         "token": contract,
#                         "owner": owner,
#                         "spender": spender_,
#                         "amount": amount,
#                         "order": order_counter[0],
#                     })
#                     order_counter[0] += 1

#         # Traverse child calls.
#         for depth, target, child_calltype, next_key in callgraph.get(contract, {}).get(call_key, []):
#             target = target.lower()

#             if child_calltype == "DELEGATECALL":
#                 # DELEGATECALL: storage/context and msg.sender are unchanged.
#                 # target executes in the context of contract.
#                 # Therefore, for the child call, address(this) remains contract and msg.sender is unchanged.
#                 dfs(target, next_key, msg_sender)
#             else:
#                 # CALL / STATICCALL:
#                 # For the child call, address(this) = target.
#                 # For the child call, msg.sender = contract, the calling contract.
#                 dfs(target, next_key, contract)

#     dfs(receiver, root_call, root_caller)

#     allowance = defaultdict(int)
#     lacking = set()

#     for e in sorted(events, key=lambda x: x["order"]):
#         token = e["token"]
#         owner = e["owner"]
#         spender = e["spender"]
#         key = (token, owner, spender)

#         if receiver not in key:
#             continue

#         if e["type"] == "approve":
#             allowance[key] = e["amount"]

#         elif e["type"] == "transferFrom":
#             if allowance[key] >= e["amount"]:
#                 allowance[key] -= e["amount"]
#             else:
#                 lacking.add(key)
#                 allowance[key] = 0

#     results = []

#     for token, owner, spender in lacking:
#         results.append({
#             "token": token,
#             "owner": owner,
#             "spender": spender,
#             "amount": "type(uint256).max"
#         })

#     func_name = "setupApprovals"
    
#     return generate_foundry_approve_function(results, receiver, func_name), f"\n\t{func_name}(address(attC));" if len(results) > 0 else ""

def generate_foundry_approve_function(
    approve_results,
    receiver,
    func_name,
    low_level=False
):
    receiver = receiver.lower()

    if not approve_results:
        return ""

    grouped = {}
    for item in approve_results:
        owner = item["owner"].lower()
        grouped.setdefault(owner, []).append(item)

    def replace_addr(addr):
        return "address(attC)" if addr.lower() == receiver else addr.lower()

    lines = []
    lines.append(f"function {func_name}(address attC) internal {{")

    for owner, items in grouped.items():
        owner_repr = replace_addr(owner)
        
        lines.append(f"\tvm.startPrank({owner_repr},{owner_repr});")

        for item in items:
            token = item["token"].lower()
            spender = replace_addr(item["spender"])
            amount = item.get("amount", "type(uint256).max")

            if low_level:
                lines.append("    {")
                lines.append(
                    f'        (bool ok, bytes memory data) = {token}.call('
                )
                lines.append(
                    f'            abi.encodeWithSignature("approve(address,uint256)", {spender}, {amount})'
                )
                lines.append("        );")
                lines.append('        require(ok, "approve call failed");')
                lines.append("        if (data.length > 0) {")
                lines.append('            require(abi.decode(data, (bool)), "approve returned false");')
                lines.append("        }")
                lines.append("    }")
            else:
                lines.append(
                    f"\tIERC20({token}).approve({spender}, {amount});"
                )

        lines.append("\tvm.stopPrank();")
    lines.append("\tvm.startPrank(attacker, attacker);")

    lines.append("\t}")

    return "\n".join(lines)

def synthesizer_deals(tokenflow, attacker, who):
    sum_tokens = {}
    max_negative_tokens = {}
    for flow in tokenflow:
        if not flow['event'] in ("Transfer", "Deposit", "Withdrawal"): continue
        if to_checksum_address(flow['from']) == to_checksum_address(attacker):
            token = to_checksum_address(flow['token'])
            if token not in sum_tokens:
                sum_tokens[token] = 0
            if token not in max_negative_tokens:
                max_negative_tokens[token] = 0
            sum_tokens[token] -= int(flow['value'], 16)
            if sum_tokens[token] < max_negative_tokens[token]:
                max_negative_tokens[token] = sum_tokens[token]

        if to_checksum_address(flow['to']) == to_checksum_address(attacker):
            token = to_checksum_address(flow['token'])
            if token not in sum_tokens:
                sum_tokens[token] = 0
            if token not in max_negative_tokens:
                max_negative_tokens[token] = 0
            sum_tokens[token] += int(flow['value'], 16)
                
    deals = []
    for token, value in max_negative_tokens.items():
        if max_negative_tokens[token] < 0:
            if token == "Native":
                deals.append(f"{IDENT*2}deal({who}, {-value/1e18} ether);")
            else:
                deals.append(f"{IDENT*2}deal(IERC20({token}), {who}, {-value});")
    return "\n" + "\n".join(deals) if len(deals) > 0 else ""

def synthesizer_logs(tokenflow, addr, benificiary_tag="attacker", flow_changes=None):
    pre_attack_logs = []
    post_attack_logs = []
    
    if flow_changes is None:
        flow_changes = {}
        for flow in tokenflow:
            if not flow['event'] in ("Transfer", "Deposit", "Withdrawal"): continue
            token, _from, _to = to_checksum_address(flow['token']), to_checksum_address(flow['from']), to_checksum_address(flow['to'])
            _from = to_checksum_address(_from)
            _to = to_checksum_address(_to)
            
            if _from not in flow_changes: flow_changes[_from] = {}
            if _to not in flow_changes: flow_changes[_to] = {}
            if token not in flow_changes[_from]: flow_changes[_from][token] = 0
            if token not in flow_changes[_to]: flow_changes[_to][token] = 0
            flow_changes[_from][token] -= int(flow['value'], 16)
            flow_changes[_to][token] += int(flow['value'], 16)

    if addr in flow_changes:
        # if int(addr, 16) == 0 : 
        #     continue
        for token in flow_changes[addr]:
            value = flow_changes[addr][token]
            # if addr == attacker:
            #     benificiary = "attacker"
            # else:
            #     benificiary = "address(attC)"
            if value > 0:
                if token != "Native":
                    if benificiary_tag != "address(attC)": # as the contract has not been created
                        pre_attack_logs.append(f"{IDENT*2}emit log_named_decimal_uint(\"before attack: balance of {benificiary_tag}\", IERC20({to_checksum_address(token)}).balanceOf({benificiary_tag}), 18);")
                    post_attack_logs.append(f"{IDENT*2}emit log_named_decimal_uint(\"after attack: balance of {benificiary_tag}\", IERC20({to_checksum_address(token)}).balanceOf({benificiary_tag}), 18);")
                else:
                    if benificiary_tag != "address(attC)": # as the contract has not been created
                        pre_attack_logs.append(f"{IDENT*2}emit log_named_decimal_uint(\"before attack: balance of {benificiary_tag}\", address({benificiary_tag}).balance, 18);")
                    post_attack_logs.append(f"{IDENT*2}emit log_named_decimal_uint(\"after attack: balance of {benificiary_tag}\", address({benificiary_tag}).balance, 18);")
                        
    return flow_changes, f'\n'.join(pre_attack_logs), f'\n'.join(post_attack_logs)    

def synthesizer_constructors(irs, payable=False):
    if not payable:
        return f"{IDENT}constructor() {{ //<PLACEHOLDER> }} "
    else:
        return f"{IDENT}constructor() payable {{ //<PLACEHOLDER> }} "
    
def synthesizer_call(irs, value, wo_adv_contracts):
    _input = irs[0][1]
    _, call, intput_, value_ = _input.split("_")
    name = get_func_name(intput_[:10])
    
    if not wo_adv_contracts:
        if value > 0:
            attack_call = f"{IDENT*2}attC.{name}{{value: {value} ether}}();"
            attack_header = f"{IDENT}function {name}() public payable {{ // <PLACEHOLDER> attack logic }}"
        else:
            attack_call = f"{IDENT*2}attC.{name}();"
            attack_header = f"{IDENT}function {name}() public {{ // <PLACEHOLDER> attack logic }}"
    else:
        attack_call = f"{IDENT*2}// <PLACEHOLDER> direct calls to the target contract in the transactions;"
        attack_header = ""
    return attack_call, attack_header

def synthesizer_attack_call(chain, senders, _irs, values, blocknumbers, wo_adv_contracts):
    attack_calls = []
    attack_functions = []
    init_value = ""
    current_sender = senders[0]
    current_blocknumber = blocknumbers[0]
    
    for i, sender, value, irs, blocknumber in zip(range(len(_irs)), senders, values, _irs, blocknumbers):
        if len(irs) == 0: continue
        _input = irs[0][1]
        calltype = _input.split("_")[1]
        if calltype in ("CREATE", "CREATE2"):
            constructor_function = synthesizer_constructors(irs, value>0)
            attack_functions.append(constructor_function)
            if i == 0 and value > 0:
                init_value = f"{{{value} ether}}"
        else:
            attack_call, attack_function = synthesizer_call(irs, value, wo_adv_contracts)
            if current_sender is None or current_sender != sender:
                current_sender = sender
                attack_calls.append(f"{IDENT*2}vm.startPrank({sender}, {sender});")
                
            if current_blocknumber is None or current_blocknumber != blocknumber:
                timestamp = get_blocktimestamp(chain, blocknumber-1)
                current_blocknumber = blocknumber
                attack_calls.append(f"{IDENT*2}vm.warp({timestamp});")
                attack_calls.append(f"{IDENT*2}vm.roll({blocknumber-1});")
            
            attack_calls.append(attack_call)
            attack_functions.append(attack_function)
            
    return init_value, "\n" + "\n".join(attack_calls) if len(attack_calls) > 0 else "", "\n".join(attack_functions)

def get_first_attack_contract(_irs):
    for irs in _irs:
        for addr, _input, ir in irs:
            addr = to_checksum_address(addr)
            return addr

def synthesizer_draft(chain, 
                      blocknumbers, 
                      deals, 
                      attack_deals,
                      pre_attack_logs, 
                      senders,
                      receiver,
                      irs, 
                      values,
                      post_attack_logs,
                      wo_adv_contracts,
                      setup_approves,
                      approves):
    global poc_template, wo_adv_poc_templates
    
    attack_contract = get_first_attack_contract(irs)
    contract_names, involved_addrs, involved_abis, unknown_addrs = get_involved_funcs(senders[0], receiver, chain, irs, wo_adv_contracts)
    
    # constructors = synthesizer_constructors(irs)
    init_value, attack_calls, attack_functions = synthesizer_attack_call(chain, senders, irs, values, blocknumbers, wo_adv_contracts)

    if not wo_adv_contracts:
        template = poc_template.format(
            involved_addrs=involved_addrs,
            chain=CHAINS.get(chain,chain),
            blocknumber=min(blocknumbers),
            deals=deals,
            attack_deals=attack_deals,
            setup_approves=setup_approves,
            attack_approves=approves,
            pre_attack_logs=pre_attack_logs,
            init_value=init_value,
            attack_calls=attack_calls,
            post_attack_logs=post_attack_logs,
            attack_contract=attack_contract,
            attack_functions=attack_functions,
            involved_abis=involved_abis
        )
    else:
        template = wo_adv_poc_templates.format(
            involved_addrs=involved_addrs,
            chain=CHAINS.get(chain,chain),
            blocknumber=min(blocknumbers),
            deals=deals,
            pre_attack_logs=pre_attack_logs,
            attack_calls=attack_calls,
            post_attack_logs=post_attack_logs,
            involved_abis=involved_abis
        )

    return contract_names, template, unknown_addrs

def replace_contract_names(ir, contract_names):
    return ir

def remove_return(trace):
    def f(line):
        if opcode(line) == "return":
            return []
        else:
            return [line]
    return rewrite_trace_ifs(trace, f)


def replace_code_data(trace):
    def f(exp):
        if (opcode(exp) == "code.data") and (concrete := get_concrete(exp)) is not None:
            return concrete
        else:
            return exp

    return replace_f(trace, f)

def replace_to_address(trace, addr, receiver):
    def f(exp):
        if type(exp) == int and to_checksum_address(hex(exp)) == to_checksum_address(addr):
            return "address"
        
        elif type(exp) == str and addr in exp:
            return exp.replace(receiver, "address")
        
        elif type(exp) == int and to_checksum_address(hex(exp)) == to_checksum_address(receiver):
            return "address(attC)"
        
        elif type(exp) == str and receiver in exp:
            return exp.replace(receiver, "address(attC)") 
        
        else:
            return exp
    return replace_f(trace, f)

def replace_cd_data(trace):
    def f(exp):
        if (opcode(exp) == "cd" or opcode(exp) == "call.data") and (concrete := get_concrete(exp)) is not None:
            return concrete
        else:
            return exp
    return replace_f(trace, f)

def replace_stor_data(trace):
    def f(exp):
        if opcode(exp) == "stor" and (concrete := get_concrete(exp)) is not None:
            return concrete
        elif opcode(exp) == "storage" and (concrete := get_concrete(exp)) is not None:
            return concrete
        else:
            return exp
    return replace_f(trace, f)

def replace_create_address(trace):
    def f(exp):
        if opcode(exp) in ("create.new_address", "create2.new_address") and (concrete := get_concrete(exp)) is not None:
            return concrete
        else:
            return exp
    return replace_f(trace, f)

def remove_static_console(trace):
    def f(line):
        if match(line, ("staticcall", Any, Any, "'console.log'", ...)):
            return []
        else:
            return [line]
    return rewrite_trace_ifs(trace, f)

def remove_store(trace):
    def f(line):
        if opcode(line) == "store":
            return []
        else:
            return [line]
    return rewrite_trace_ifs(trace, f)

def remove_log(trace):
    def f(line):
        if opcode(line) == "log":
            return []
        else:
            return [line]
    return rewrite_trace_ifs(trace, f)

def remove_callvalue_check(ir):
    return ir

def replace_concrete_data(ir, addr, receiver):
    ir = replace_code_data(ir)
    ir = replace_cd_data(ir)
    ir = replace_to_address(ir, addr, receiver)
    return ir

class ClenupCondSettings:
    def __init__(self):
        self.attrs = ["rm_sha3_conds", "rm_caller_conds", "prettify_div10"]
        pass
    
    def __enter__(self):
        for attr in self.attrs:
            if not hasattr(settings, attr):
                raise ValueError(f"settings has no attribute {attr}")
            setattr(settings, attr, True)    

    def __exit__(self, exc_type, exc_val, exc_tb):
        for attr in self.attrs:
            if not hasattr(settings, attr):
                raise ValueError(f"settings has no attribute {attr}")
            setattr(settings, attr, False)
    
def ir_to_llm(ir, contract_names, addr, receiver, is_constructor=False):
    attacks_in_params = False
    if is_constructor:
        ir = remove_return(ir)
    ir = remove_static_console(ir)
    # ir = remove_callvalue_check(ir)
    # ir = replace_contract_names(ir, contract_names)
    ir = replace_create_address(ir)
    ir = replace_stor_data(ir)
    ir = remove_store(ir)
    ir = remove_log(ir)


    if not settings.tracexp_as_1:
        old_ir = ir
        ir = replace_concrete_data(old_ir, addr, receiver)
        if ir != old_ir:
            attacks_in_params = True

    with ClenupCondSettings():
        ir = cleanup_conds(ir)
    
    settings.wo_concrete = True
    settings.prettify_code = True
    ir = rewrite_trace_full(ir, rewrite_call_args)
    settings.prettify_abi_encode = True
    
    if not settings.tracexp_as_2:
        settings.prettify_call_idx = True
        settings.assume_require = True
        ir = path_compressor(ir)
        settings.prettify_call_idx = False
        settings.assume_require = False
    
    return trace_to_str(ir), attacks_in_params

def irs_to_llm(contract_names, unknown_addrs, irs, receiver, wo_adv_contracts, values):
    attacks_in_params = False
    text_irs = ""
    contracts = {}
    to_inferred_names = set()
    for addr, _input, ir in irs:
        addr = to_checksum_address(addr)
        _, call, intput_, value_ = _input.split("_")
        if call in ("CREATE", "CREATE2"):
            name = "constructor"
        else:
            name = get_func_name(intput_[:10])
        if name.startswith("unknown"):
            to_inferred_names.add(name)
        if addr not in contracts:
            contracts[addr] = dict()
        if _input not in contracts[addr]:
            contracts[addr][_input] = []
        contracts[addr][_input].append(ir)

    for addr, contracts in contracts.items():
        addr = to_checksum_address(addr)
        text_irs += f"### Contract: {contract_names.get(addr, addr)}\n"
        for _input, irs in contracts.items():
            _, call, intput_, value_ = _input.split("_")
            if call in ("CREATE", "CREATE2"):
                text_irs += f"#### Constructor:\n"
            else:
                text_irs += f"#### Transaction: {addr}.{decode_abi(intput_[:10], intput_[10:], value=value_, anyway=wo_adv_contracts)}\n"
            if not wo_adv_contracts:
                for ir in irs:
                    text, in_params = ir_to_llm(ir, contract_names, addr, receiver, is_constructor=(call in ("CREATE", "CREATE2")))
                    attacks_in_params |= in_params
                    text_irs += text.strip("\n") + "\n"

    text_to_inferred_names = ""
    # if len(to_inferred_names | unknown_addrs) > 0:
    #     text_to_inferred_names += f"\n### Names To Be Inferred:\n"
    #     if len(to_inferred_names) > 0:
    #         text_to_inferred_names += "function names: "
    #         text_to_inferred_names += ", ".join(to_inferred_names) + "\n"
    #     if len(unknown_addrs) > 0:
    #         text_to_inferred_names += "variable names: "
    #         text_to_inferred_names += ", ".join(sorted(unknown_addrs)) + "\n"
    
    return text_to_inferred_names, attacks_in_params, text_irs

def build_user_prompt(irs, contract_names, unknown_addrs, receiver, draft, wo_adv_contracts, values):
    global synthesis_user_prompt
    
    to_inferred_names, attacks_in_params, text_irs = irs_to_llm(contract_names, unknown_addrs, irs, receiver, wo_adv_contracts, values)
    
    return attacks_in_params, text_irs, synthesis_user_prompt.format(
        poc_template=draft,
        executions=text_irs,
        to_inferred_names=to_inferred_names
    )
    
def synthesizer_prompt(chain, 
                blocknumbers, 
                deals, 
                attack_deals,
                pre_attack_logs, 
                senders,
                receiver,
                irs, 
                values, 
                post_attack_logs,
                wo_adv_contracts,
                support_revert,
                setup_approves,
                approves):
    global synthesis_sys_prompt
    contract_names, draft, unknown_addrs = synthesizer_draft(chain=chain,
                                              blocknumbers=blocknumbers,
                                              deals=deals,
                                              attack_deals=attack_deals,
                                              pre_attack_logs=pre_attack_logs,
                                              senders=senders,
                                              receiver=receiver,
                                              irs=irs,
                                              values=values,
                                              post_attack_logs=post_attack_logs,
                                              wo_adv_contracts=wo_adv_contracts,
                                              setup_approves=setup_approves,
                                              approves=approves)
    
    concat_irs = []
    for ir in irs:
        concat_irs.extend(ir)
    
    attacks_in_params, text_irs, user_prompt = build_user_prompt(concat_irs, 
                                                                 contract_names, 
                                                                 unknown_addrs, 
                                                                 receiver,
                                                                 draft=draft, 
                                                                 wo_adv_contracts=wo_adv_contracts,
                                                                 values=values)
    
    if not support_revert:
        revert_ins = ""
    else:
        revert_ins = "\n- Implement fault-tolerant logic so that a single revert or failed external call does not halt the entire transaction execution (e.g., use try/catch, low-level calls, or conditional checks to handle errors gracefully)."
    
    sys_prompt = synthesis_sys_prompt.format(revert_ins=revert_ins, examples=CALL_IDENTITY_EXAMPLES)
    
    return sys_prompt, user_prompt, attacks_in_params, text_irs

def synthesizer_poc(sys_prompt, user_prompt, llm_client, code_path):
    prompt = make_prompt(llm_client, sys_prompt=sys_prompt, user_prompt=user_prompt)
    response, _ = make_request(llm_client, prompt)
    if response:
        syn_response = response["choices"][0]["message"]["content"]
        
        code = extract_code_from_content(syn_response)
        
        write_code_to_file(code, code_path)
        return {
            "code_path": code_path,
            "responses": [response],
            "prompt_tokens": response["usage"]["prompt_tokens"],
            "completion_tokens": response["usage"]["completion_tokens"],
        }
    else:
        return {
            "code_path": None,
            "responses": [],
            "prompt_tokens": 0,
            "completion_tokens": 0,
        }