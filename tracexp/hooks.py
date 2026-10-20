from panoramix.utils.helpers import opcode, get_concrete, get_hooked, get_pc
from panoramix.simplify import simplify_exp
from panoramix.utils.opcode_dict import stack_writes

import panoramix.settings as settings

# update trace
memops = (
    "extcodecopy",
    "codecopy",
    "calldatacopy",
    "returndatacopy"
)

createops = (
    "create",
    "create2"
)

callops = (
    "call",
    "callcode",
    "delegatecall",
    "staticcall"
)

# update stacks
jumpops = (
    "jump",
    "jumpi"
)

storops = (
    "sload",
    "tload"
)

stackops = (
    "returndatasize",
    "calldatasize",
    "calldataload",
    "codesize", 
    "extcodesize"
)

pcops = (
    "log",
    "callcode",
    "delegatecall",
    "staticcall",
    "call",
    "selfdestruct",
    "create",
    "create2",
    "precompiled",
    "setvar",
    "setmem",
    "store",
    "set",
    "stop",
    "return",
    "revert",
    "tstore",
    "funccall",
    "if"
)

balanceops = (
    "balance",
    "selfbalance"
)

blockstates = (
    "coinbase",
    # "address",
    # "timestamp",
    "blockhash",
    "number",
    "difficulty",
    "chainid",
    "basefee",
    "blobhash",
    "blobbasefee",
    # "gas",
    # "gaslimit",
    # "gasprice"
)

def get_param_hook(op, next_op=None):
    pc, opname = op["pc"], op["opName"]        
    param = None
    opname = opname.lower()
    
    if opname in memops + callops + createops + jumpops + storops + stackops + balanceops + blockstates:
        if opname in memops + callops + createops:
            if 'output' in op:
                param = op['output']                        
            else:
                # assume that no returns
                param = ""
        elif opname in jumpops:
            assert next_op is not None, f"Jump instruction {opname} at {pc} has no next operation"
            target = next_op['pc']
            dest = op['pops'][0]
            if isinstance(dest, str):
                if not dest.startswith("0x"):
                    dest = "0x" + dest
                dest = int(dest, 16)
                                
            if opname == "jump":
                param = dest
            else:
                param = target == dest
            
        else:
            param = op['pushes'][0]
            if isinstance(param, str):
                if not param.startswith("0x"):
                    param = "0x" + param
                param = int(param, 16)
    return param

def add_pc(exp, pc):
    if get_pc(exp) is not None:
        return exp
    
    if type(exp) == str:
        exp = (exp, )

    if type(exp) != tuple or len(exp) == 0:
        return exp
    
    if opcode(exp[-1]) == "hooked":
        hook = exp[-1]
        exp = exp[:-1] + (("hooked", ("pc", pc), hook[2]),)
        return exp

    else:
        return exp + (("hooked", ("pc", pc), ("concrete", None)),)

def add_concrete(exp, concrete, name="concrete"):
    if get_concrete(exp) is not None:
        return exp

    if type(exp) == str:
        exp = (exp, )

    if type(exp) != tuple or len(exp) == 0:
        return exp

    if opcode(exp[-1]) == "hooked":
        hook = exp[-1]
        exp = exp[:-1] + (("hooked", hook[1], (name, concrete)),)
        return exp
    else:
        return exp + (("hooked", ("pc", None), (name, concrete)), )

# ignore , "returndatacopy"
def op_to_concrete(op):
    if not settings.tracexp_as_1 and op in ("calldatacopy", "calldatasize", "calldataload",
              "codecopy", "extcodecopy", "codesize", "extcodesize",
              "returndatasize") + storops + blockstates:
        return True
    return False

def add_pc_hook(line, trace, stack, trace_changes):
    pc = line[0]
    
    if trace_changes > 0 and type(trace[-1]) == tuple:
        op = opcode(trace[-1])

        if op in pcops:
            trace[-1] = add_pc(trace[-1], pc)
            
            if op == "setmem" and len(trace) >= 2 and opcode(trace[-2]) in callops + ("precompiled", ):
                trace[-2] = add_pc(trace[-2], pc)

def add_concrete_hook(line, trace, stack, trace_changes):
    op, concrete = line[1], line[2]
    
    # setmem
    if op in memops + callops + createops and trace_changes > 0:
        if opcode(trace[-1]) == "setmem":
            mrange, value = trace[-1][1], trace[-1][2]
            hooked = get_hooked(trace[-1])
            if not settings.tracexp_as_1 and op_to_concrete(op):
                trace[-1] = ("setmem", mrange, concrete)
            else:
                trace[-1] = ("setmem", mrange, add_concrete(value, concrete))
            if hooked is not None:
                trace[-1] += (hooked, )
        elif opcode(trace[-1]) in createops:
            trace[-1] = add_concrete(trace[-1], concrete, "address")                
            stack.stack[-1] = add_concrete(stack.stack[-1], concrete)
    
    elif op in storops + stackops + balanceops + blockstates:
        last_exp = stack.stack[-1]
        if not settings.tracexp_as_1 and op_to_concrete(op):
            stack.stack[-1] = concrete
        else:
            stack.stack[-1] = add_concrete(last_exp, concrete)
        
    elif op in stack_writes and stack_writes[op] > 0:
        for i in range(stack_writes[op]):
            if type(stack.stack[-(i+1)]) != int:            
                stack.stack[-(i+1)] = simplify_exp(stack.stack[-(i+1)])