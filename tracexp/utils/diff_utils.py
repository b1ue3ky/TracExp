import re

from panoramix.loader import Loader
from tracexp.utils.helpers import get_func_name, cached
from tracexp.utils.web3_helpers import to_checksum_address


def bytes_to_hex(obj):
    if isinstance(obj, bytes):
        return '0x' + obj.hex()  # bytes → hex str
    elif isinstance(obj, tuple):
        return tuple(bytes_to_hex(x) for x in obj)
    elif isinstance(obj, list):
        return [bytes_to_hex(x) for x in obj]
    else:
        return obj

@cached
def loader_decode_hex(hex_input):
    if not hex_input.startswith("0x"):
        hex_input = "0x" + hex_input
    if hex_input == "0x":
        return "fallback", None, ""

    name, types, decoded = Loader.abi_decode(hex_input[:10], bytes.fromhex(hex_input[10:]))
    
    if name != None:
        decoded = bytes_to_hex(decoded)
    
    return name, types, decoded
        
def decode_hex(hex_input):
    name, types, decoded = loader_decode_hex(hex_input)
        
    if name != None:    
        return f"{name}({decoded})"
    else:
        return f"call({hex_input})"
    # else:
    #     return f"unknown{hex_input[:10]}({hex_input[10:]})"

def split_top_level(s):
    parts, buf, depth = [], "", 0
    for ch in s:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf:
        parts.append(buf.strip())
    return parts

def normalize_value(v):
    if not v:
        return v
    
    v = v.strip()
    
    colon_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(\[.+\])$', v)
    if colon_match:
        v = colon_match.group(2)[1:-1].strip()
            
    sci_notation_match = re.match(r'^(.*?)\s+\[([0-9.]+[eE][+-]?[0-9]+)\]$', v)
    if sci_notation_match:
        v = sci_notation_match.group(1).strip()
    
    if isinstance(v, str) and v.lower().startswith("0x"):
        hex_part = v[2:]
        if hex_part and all(c in "0123456789abcdefABCDEF" for c in hex_part):
            return v.lower()

    if v.startswith("[") and v.endswith("]"):
        inner_content = v[1:-1].strip()
        
        if not inner_content:
            return ()
        
        inner = split_top_level(inner_content)
        
        if len(inner) == 1:
            normalized = normalize_value(inner[0])
            return (normalized,)
        
        return tuple(normalize_value(x) for x in inner if x.strip())
    
    if v.startswith("(") and v.endswith(")"):
        inner_content = v[1:-1].strip()
        
        if not inner_content:
            return ()
        
        inner = split_top_level(inner_content)
        
        return tuple(normalize_value(x) for x in inner if x.strip())

    if v.isdigit():
        return int(v)
    
    if v.startswith("-") and v[1:].isdigit():
        return int(v)
    
    cleaned_num = v.replace("_", "")
    if cleaned_num.isdigit():
        return int(cleaned_num)

    return v


def normalize_param_string(s):
    items = split_top_level(s)
    return tuple(normalize_value(x) for x in items if x)

def prettify_call_line(creates_seq, forge_creates_seq, forge_new_addresses, line, is_forge:bool=True):
    _, caller, callee, selector, input, ret, context = get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, line, is_foundry=is_forge)

    # callee = line[1]
    # _input = line[-2] if is_forge else line[-1]
    
    if callee in creates_seq:
        callee = forge_creates_seq[creates_seq.index(callee)]
    
    if is_forge:
        # depth, call, input = _input.split("_")
        if input == '0x':
            selector = "fallback"
            input = ""
            
        if len(ret) > 0 and ret != "()":
            return f"{to_checksum_address(callee)}.{selector}{input} → {ret}"
        else:
            return f"{to_checksum_address(callee)}.{selector}{input}"
    else:
        # depth, call, input, value = _input.split("_")
        # return f"{to_checksum_address(callee)}.{decode_hex(input)}"
        
        _input = line[-1]
        try:
            depth, call, input, value = _input.split("_")
        except:
            depth, call, input = _input.split("_")
            value = 0
        if input == "0x":
            return f"{to_checksum_address(callee)}.fallback()"
        else:
            if len(input) > 10: input = replace_input(creates_seq, forge_creates_seq, forge_new_addresses, input)
            selector, _, params = loader_decode_hex(input)
            
            if selector is None:
                return f"{to_checksum_address(callee)}.call({input[2:]})"    
        
            def args_to_str(args):
                if args is None:
                    return ""
                if type(args) in (tuple, list):
                    return "("+",".join(args_to_str(a) for a in args)+")"
                if type(args) == str and not args.startswith("0x"):
                    return "0x" + args
                return str(args)

            # params = args_to_str(params)

            if type(params) in (list, tuple):
                params = ",".join(args_to_str(a) for a in params)
            
            params = postprocess_params(creates_seq, forge_creates_seq, forge_new_addresses, params, is_forge=False)
            return f"{to_checksum_address(callee)}.{selector}{params}"    
        
    
def replace_input(creates_seq, forge_creates_seq, forge_new_addresses, input):
    for i, address in enumerate(forge_creates_seq):
        if i < len(creates_seq):
            input = input.replace(creates_seq[i][2:], forge_new_addresses[address][2:].lower())
    return input

def postprocess_params(creates_seq, forge_creates_seq, forge_new_addresses, params, is_forge:bool=True):
    def repl(match):
        return match.group(2).lower()
    
    if is_forge:
        pattern = r"\b(" + "|".join(map(re.escape, forge_creates_seq)) + r"):\s*\[(.*?)\]"
        r = re.sub(pattern, repl, params, flags=re.IGNORECASE)
        r = normalize_param_string(r)
        return r
    else:
        for i in range(min(len(creates_seq), len(forge_creates_seq))):
            address = creates_seq[i]
            params = params.replace(address[2:], forge_new_addresses[forge_creates_seq[i]][2:].lower())
        return normalize_param_string(params)

# depth, callee, func, params
def get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, line, is_foundry:bool=True):
    unknown_selector = r'unknown([a-fA-F0-9]{8})(?:\{[^}]*\})?\(([^)]*)\)'
    other_selector = r'([a-zA-Z0-9_]*)(?:\{[^}]*\})?\(([^)]*)\)'
    
    if is_foundry:
        caller = line[2]
        callee = line[3]
        if callee in forge_new_addresses:
            pass
        else:
            callee = to_checksum_address(callee)
        _ret = line[-2]
        _input = line[-3]
        if is_foundry:
            depth, call, contract, input = _input.split("_",3) # for except _BASE_TOKEN_
            _context = f"{contract}.{input}"
        else:
            depth, call, input, value = _input.split("_")
        if match := re.search(unknown_selector, input):
            selector = "unknown" + match.group(1)
            params = match.group(2)
            
        elif match := re.search(other_selector, input):
            selector = match.group(1)
            try:
                int("0x" + selector, 16)
                selector = get_func_name("0x" + selector)
            except:
                pass
            params = match.group(2)
            
        else:
            assert False, f"Cannot parse the input {input}"
        
        if selector in ("receive", "fallback"):
            selector = "0x"
        
        return int(depth), caller, callee, selector, postprocess_params(creates_seq, forge_creates_seq, forge_new_addresses, params, is_forge=True), _ret, _context
    else:
        caller = line[1]
        callee = line[2]
        if callee in creates_seq and creates_seq.index(callee) < len(forge_creates_seq):
            callee = forge_creates_seq[creates_seq.index(callee)]
        else:
            callee = to_checksum_address(callee)

        _input = line[-1]
        try:
            depth, call, input, value = _input.split("_")
        except:
            depth, call, input = _input.split("_")
            value = 0
        selector, _, params = loader_decode_hex(input)
        
        if selector is None:
            selector = get_func_name(input[:10])
            params = input[10:]
        
        def args_to_str(args):
            if args is None:
                return ""
            if type(args) in (tuple, list):
                return "("+",".join(args_to_str(a) for a in args)+")"
            if type(args) == str and not args.startswith("0x"):
                return "0x" + args
            return str(args)

        # params = args_to_str(params)

        if type(params) in (list, tuple):
            params = ",".join(args_to_str(a) for a in params)
        
        params = postprocess_params(creates_seq, forge_creates_seq, forge_new_addresses, params, is_forge=False)
        return int(depth), caller, callee, selector, params, None, None
    
    
def locate_param_diff_flatten_line(forge_line, s, flattened, creates_seq, forge_creates_seq, forge_new_addresses):
    error_forge_depth, error_forge_caller, error_forge_callee, error_forge_func, error_forge_params, error_forge_ret, error_forge_context = get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, forge_line, is_foundry=True)
    
    if error_forge_caller in forge_creates_seq:
        for i in range(25):
            for j in [-1, 1]:
                if 0 <= s + i * j < len(flattened):
                    current_line = flattened[s + i * j]
                    depth, caller, callee, func, params, _, _ = get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, current_line, is_foundry=False)
                    
                    if depth == error_forge_depth and callee == error_forge_callee and func == error_forge_func and params != error_forge_params:
                        return current_line

        current_line = flattened[s]
        depth, caller, callee, func, params, _, _ = get_call_info(creates_seq, forge_creates_seq, forge_new_addresses, current_line, is_foundry=False)
        
        if depth == error_forge_depth and callee == error_forge_callee and func != error_forge_func:
            return current_line
            
    return None