import json
import os
import re

# import sha3
from eth_hash.auto import keccak
from web3 import HTTPProvider, Web3
from web3.middleware import ExtraDataToPOAMiddleware

from panoramix.utils.supplement import insert_signatures_to_database, fetch_abi
from tracexp.utils.helpers import (CACHE_DIR, cached, read_json, request_url,
                               try_import_value, write_json)


@cached
def to_checksum_address(address):
    try:
        return Web3.to_checksum_address("0x" + address[2:].rjust(40,"0"))
    except:
        return address
    
def build_provider(endpoint_uri):
    if endpoint_uri.startswith("http"):
        provider = HTTPProvider(
            endpoint_uri,
            {"timeout": 600}
        )
    else:
        raise ValueError("Invalid endpoint URI")
    
    return provider

def build_web3(provider):
    w3 = Web3(provider)
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3

def get_endpoint_uri(chain:str):
    env_name = {
        "eth": "ETH_RPC_URL",
        "bsc": "BSC_RPC_URL",
    }.get(chain)
    if env_name is None:
        raise ValueError(f"Unsupported chain: {chain}")

    endpoint = os.environ.get(env_name)
    if not endpoint:
        raise ValueError(f"Set {env_name} to an RPC endpoint with debug support")

    return endpoint

def get_blocktimestamp(chain, blocknumber):
    block_path = f"{CACHE_DIR}/block/{chain}/{blocknumber}.json"
    os.makedirs(os.path.dirname(block_path), exist_ok=True)
    if os.path.exists(block_path):
        block = read_json(block_path)
        return block['timestamp']
    else:
        w3 = build_web3(build_provider(get_endpoint_uri(chain)))
        block = w3.eth.get_block(blocknumber)
        block = Web3.to_json(block)
        if type(block) == str:
            block = json.loads(block)
        write_json(block_path, block)
    return block['timestamp']

@cached    
def get_transaction_receipt(chain, tx_hash):
    receipt_path = f"{CACHE_DIR}/receipt/{chain}/{tx_hash}.json"
    os.makedirs(os.path.dirname(receipt_path), exist_ok=True)
    if os.path.exists(receipt_path):
        receipt = read_json(receipt_path)
        return receipt
    else:
        
        w3 = build_web3(build_provider(get_endpoint_uri(chain)))
        receipt = Web3.to_json(w3.eth.get_transaction_receipt(tx_hash))
        if type(receipt) == str:
            receipt = json.loads(receipt)
        write_json(receipt_path, receipt)
    return receipt

@cached
def get_transaction_logs(chain, tx_hash):
    receipt = get_transaction_receipt(chain, tx_hash)
    
    if 'logs' in receipt:
        return receipt['logs']
    else:
        return []

@cached
def get_transaction(chain, tx_hash):
    transaction_path = f"{CACHE_DIR}/transaction/{chain}/{tx_hash}.json"
    os.makedirs(os.path.dirname(transaction_path), exist_ok=True)
    if os.path.exists(transaction_path):
        transaction = read_json(transaction_path)
        return transaction
    else:
        w3 = build_web3(build_provider(get_endpoint_uri(chain)))
        transaction = w3.eth.get_transaction(tx_hash)
        
        if transaction is None:
            return None
        
        transaction = Web3.to_json(transaction)
        if type(transaction) == str:
            transaction = json.loads(transaction)
        write_json(transaction_path, transaction)    
    return transaction

@cached
def get_transaction_blocknumber(chain, tx_hash):
    receipt = get_transaction_receipt(chain, tx_hash)
        
    if 'blockNumber' in receipt:
        return receipt['blockNumber']
    else:
        return -1

@cached
def get_transaction_value(chain, tx_hash):
    transaction = get_transaction(chain, tx_hash)
    
    if transaction is None:
        return None
    
    if 'value' in transaction:
        return hex(transaction['value']) # normalize to hex

    return None

@cached
def explorer_url(chain, action, address):
    explorers = {
        "eth": "https://api.etherscan.io/api",
        "bsc": "https://api.bscscan.com/api",
    }
    base_url = explorers.get(chain)
    api_key = os.environ.get("ETHERSCAN_API_KEY")
    if base_url is None or not api_key:
        return None

    return (
        f"{base_url}?module=contract&action={action}"
        f"&address={address}&apikey={api_key}"
    )


def is_erc20(chain, address):
    abi = get_contract_abi(chain, address)
    if abi is not None:
        return all(
            any(func['name'] == name for func in abi if func['type'] == 'function') 
            for name in ['totalSupply', 'balanceOf', 'transfer', 'transferFrom', 'approve', 'allowance']
        )
    return False

@cached
def get_contract_name(chain, address):
    source_path = f"{CACHE_DIR}/source_code/{address}.json"

    if os.path.exists(source_path):
        source_code = read_json(source_path)
        return source_code.get('ContractName', None)
    else:
        eth_url = explorer_url(chain, "getsourcecode", address)
        if eth_url is None:
            return None

        res = request_url(eth_url)
        if res is not None:
            res = res[0]
            write_json(source_path, res)
            return res.get('ContractName', None)
    return None

@cached
def get_evm_version(address):
    source_path = f"{CACHE_DIR}/source_code/{address}.json"

    if os.path.exists(source_path):
        source_code = read_json(source_path)
        return source_code.get('EVMVersion', 'Default')

    return 'Default'


def read_addresses_from_code_file(file_path):
    addresses = set()
    pattern = re.compile(r'address constant (\w+\s*)=\s*(0x[a-fA-F0-9]{40});')
    
    with open(file_path, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                name = match.group(1).strip()
                address = match.group(2).strip()
                if name != "attacker":
                    addresses.add(address)

    return addresses

def read_evm_version_from_code_file(file_path):
    has_shanghai = False
    has_cancun = False
    addresses = read_addresses_from_code_file(file_path)
    for address in addresses:
        evm_version = get_evm_version(address)
        if evm_version.lower() == "cancun":
            has_cancun = True
        if evm_version.lower() == "shanghai":
            has_shanghai = True

    if has_cancun: return "cancun"
    if has_shanghai: return "shanghai"
    return "default"

@cached
def get_proxy_implementation(chain, address):
    source_path = f"{CACHE_DIR}/source_code/{address}.json"

    if os.path.exists(source_path):
        source_code = read_json(source_path)
        return source_code.get('Implementation', None)
    else:
        eth_url = explorer_url(chain, "getsourcecode", address)
        if eth_url is None:
            return None

        res = request_url(eth_url)
        if res is not None:
            res = res[0]
            write_json(source_path, res)
            return res.get('Implementation', None)
    return None

def check_contract_abi(chain, addresses):
    for address in addresses:
        abi = get_contract_abi(chain, address)
        if abi is not None:
            return True
    return False

@cached
def get_contract_abi(chain, address):
    """
    Fetch the contract ABI from a local file or a remote source.
    """
    abi_path = f"{CACHE_DIR}/abi/{address}.json"
    if os.path.exists(abi_path):
        abi = read_json(abi_path)
        add_signature(abi)
        return abi
    else:
        eth_url = explorer_url(chain, "getabi", address)
        if eth_url is None:
            return None

        res = request_url(eth_url)
        
        if res is not None:
            try:
                if res:
                    if type(res) == str:
                        res = json.loads(res)
            except:
                return None
            add_signature(res)
            write_json(abi_path, res)
            return res
    
    return None

# def get_sha3(to_sha):
#     s = sha3.keccak_256()
#     s.update(to_sha.encode("utf8"))
#     return "0x" + s.hexdigest()[:8]

def get_sha3(to_sha):
    h = keccak(to_sha.encode("utf8"))
    return "0x" + h.hex()[:8]

def canonical_type(param):
    t = param["type"]

    # tuple / tuple[] / tuple[2] / tuple[][3] / tuple[tuple]
    if t.startswith("tuple"):
        suffix = t[len("tuple"):] 
        components = param.get("components", [])
        inner = ",".join(canonical_type(c) for c in components)
        return f"({inner}){suffix}"

    return t

def function_signature(abi):
    name = abi.get("name", "")
    inputs = abi.get("inputs", [])
    input_types = ",".join(canonical_type(i) for i in inputs)
    return f"{name}({input_types})"

def add_signature(abis):
    signatures = []
    for abi in [obj for obj in abis if obj['type'] == 'function']:
        signature = function_signature(abi)
        selector = get_sha3(signature)
        
        inputs = abi.get("inputs", [])
        name = abi.get("name", "")
        outputs = abi.get("outputs", [])
                
        # Create the signature dictionary
        signatures.append({
            "hash": selector,
            "name": name,
            "type": "function",
            "inputs": inputs,
            "outputs": outputs
        })
    
    if signatures:
        insert_signatures_to_database(signatures)

# def resolve_components(components, struct_name):
#     s = ""
#     c = "\t" + f"struct {struct_name} " + "{\n"
#     for comp in components:
#         ctype = comp["type"]
#         cname = comp["name"]
#         if ctype.startswith("tuple"):  # struct type
#             component_type = comp['internalType'].split('.')[-1]
#             c += "\t\t" + f"{component_type} {cname};\n"
#             s += resolve_components(comp.get('components', []), component_type) + "\n"
#         else:
#             c += "\t\t" + f"{ctype} {cname};\n"
#     c += "\t" + "};\n"
#     return s + c

# def pprint_abi(abi):
#     s = ""

#     inputs = abi.get("inputs", [])
#     outputs = abi.get("outputs", [])
#     name = abi.get("name", "")
#     # Generate the selector
#     input_types = []
#     for _input in inputs:
#         _type = _input['type']
#         if _type != "tuple":
#             input_types.append(_type)
#         else:
#             component_type = _input['internalType'].split('.')[-1]
#             s += resolve_components(_input.get('components', []), component_type) + "\n"
#             input_types.append(component_type)
            
#     if len(outputs) > 0:
#         return s + "\t" + f"function {name}({', '.join(input_types)}) external returns ({', '.join([output['type'] for output in outputs])});"
#     else:
#         return s + "\t" + f"function {name}({', '.join(input_types)}) external;"

def extract_struct_name(param, default="UnnamedStruct"):
    internal = param.get("internalType", "")
    if internal.startswith("struct "):
        return internal[len("struct "):].split(".")[-1]
    return default


def resolve_components(components, struct_name, seen=None):
    if seen is None:
        seen = set()

    # Avoid emitting the same struct more than once.
    if struct_name in seen:
        return ""
    seen.add(struct_name)

    nested_structs = ""
    body = "\t" + f"struct {struct_name} " + "{\n"

    for comp in components:
        ctype = comp["type"]
        cname = comp["name"]

        if ctype.startswith("tuple"):
            component_type = extract_struct_name(comp, "UnnamedStruct")
            suffix = ctype[len("tuple"):]  # Preserve suffixes such as [] and [2].

            nested_structs += resolve_components(
                comp.get("components", []),
                component_type,
                seen,
            )
            body += "\t\t" + f"{component_type}{suffix} {cname};\n"
        else:
            body += "\t\t" + f"{ctype} {cname};\n"

    body += "\t" + "}\n"
    return nested_structs + body + "\n"


def format_param(param, seen=None, emit_structs=None):
    if seen is None:
        seen = set()
    if emit_structs is None:
        emit_structs = []

    ptype = param["type"]
    pname = param.get("name", "")

    if ptype.startswith("tuple"):
        struct_name = extract_struct_name(param, "UnnamedStruct")
        suffix = ptype[len("tuple"):]  # "", "[]", "[2]" ...

        struct_def = resolve_components(param.get("components", []), struct_name, seen)
        if struct_def:
            emit_structs.append(struct_def)

        # Add calldata for struct parameters to match normal Solidity interfaces.
        if pname:
            return f"{struct_name}{suffix} calldata {pname}"
        return f"{struct_name}{suffix}"
    else:
        if pname:
            return f"{ptype} {pname}"
        return ptype


def pprint_abi(abi, use_low_level=False):
    seen = set()
    struct_defs = []

    inputs = abi.get("inputs", [])
    outputs = abi.get("outputs", [])
    name = abi.get("name", "")

    input_params = [format_param(x, seen, struct_defs) for x in inputs]
    output_types = []

    for output in outputs:
        otype = output["type"]
        if otype.startswith("tuple"):
            struct_name = extract_struct_name(output, "UnnamedStructOut")
            suffix = otype[len("tuple"):]
            struct_def = resolve_components(output.get("components", []), struct_name, seen)
            if struct_def:
                struct_defs.append(struct_def)
            output_types.append(f"{struct_name}{suffix}")
        else:
            output_types.append(otype)

    s = "".join(struct_defs)

    if len(outputs) > 0:
        s = s + "\t" + f"function {name}({', '.join(input_params)}) external returns ({', '.join(output_types)});"
    else:
        s = s + "\t" + f"function {name}({', '.join(input_params)}) external;"

    if use_low_level:
        s = s + f"\t// Return value is uncertain; prefer low-level call"

    return s

@cached
def get_func_interface(chain, address, func_sig):
    abis = get_contract_abi(chain, address)
    if abis is not None:
        for abi in [obj for obj in abis if obj['type'] == 'function']:
            inputs = abi.get("inputs", [])
            name = abi.get("name", "")
            
            # Generate the selector
            input_types = []
            for _input in inputs:
                _type = _input['type']
                if _type != "tuple":
                    input_types.append(_type)
                else:
                    component_types = [_['type'] for _ in _input.get('components', [])]
                    input_types.append(f"({','.join(component_types)})")
            signature = f"{name}({','.join(input_types)})"
            selector = get_sha3(signature)
            
            if selector == func_sig:
                return pprint_abi(abi)
            
        if (implementation:=get_proxy_implementation(chain, address)) is not None and implementation != address:
            return get_func_interface(chain, implementation, func_sig)

    if (abi:= fetch_abi(func_sig)) is not None:
        return pprint_abi(abi, use_low_level=True)
    return None

@cached
def get_allowance(chain, token, owner, spender, blocknumber=None):
    w3 = build_web3(build_provider(get_endpoint_uri(chain)))
    token = to_checksum_address(token)
    owner = to_checksum_address(owner)
    spender = to_checksum_address(spender)
    erc20_abi = [{
            "constant": True,
            "inputs": [
                {"name": "_owner", "type": "address"},
                {"name": "_spender", "type": "address"}
            ],
            "name": "allowance",
            "outputs": [{"name": "remaining", "type": "uint256"}],
            "type": "function",
        }
    ]
    contract = w3.eth.contract(address=token, abi=erc20_abi)
    
    allowance = contract.functions.allowance(owner, spender).call(block_identifier=blocknumber)
    return allowance

@cached
def has_allowance(chain, token, owner, spender, blocknumber=None):
    try:
        allowance = get_allowance(chain, token, owner, spender, blocknumber)
        return allowance > 0
    except:
        return False