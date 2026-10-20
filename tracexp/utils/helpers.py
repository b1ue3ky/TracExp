import json
import os
import re
import warnings
from pathlib import Path
from shutil import copyfile
from subprocess import DEVNULL, PIPE, Popen
from typing import List

import pandas as pd
import requests
from eth_abi import decode

warnings.filterwarnings("ignore")

from panoramix.loader import LOADER_TIMEOUT, Loader
from panoramix.utils.supplement import fetch_sig

CACHE_DIR = ".tracexp_cache"

# version = "0.8.29"
version = os.environ.get("VERSION", "1.0.1")
DST_DIR = f"{CACHE_DIR}/result/result_{version}"
os.makedirs(DST_DIR, exist_ok=True)

def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'''
        \x1B  # ESC
        (?:   # 7-bit C1 Fe (except CSI)
            [@-Z\\-_]
        |     # or [ for CSI, followed by a control sequence
            \[
            [0-?]*  # Parameter bytes
            [ -/]*  # Intermediate bytes
            [@-~]   # Final byte
        )
    ''', re.VERBOSE)
    return ansi_escape.sub('', text)

def remove_color_annotations(file_path):
    if os.path.exists(file_path):
        s = ""
        with open(file_path, "r") as file:
            text = file.read()
            clean_text = remove_ansi_escape_sequences(text)
            # print(clean_text)
            s += clean_text

        with open(f"{file_path + '.cleaned'}", "w") as file:
            file.write(s)

def cached(func):
    cache = {}

    def wrapper(*args, **kwargs):
        key = args + tuple(kwargs.items())
        try:
            return cache[key]
        except TypeError:  # If it contains lists.
            return func(*args, **kwargs)
        except KeyError:
            pass
        ret = func(*args, **kwargs)
        cache[key] = ret
        return ret

    return wrapper

def prepare_foundry_files(dst_dir):
    data_dir = Path(__file__).resolve().parents[1] / "data" / "foundry"
    dst_dir = os.path.abspath(dst_dir)
    os.makedirs(dst_dir, exist_ok=True)

    for file in ("basetest.sol", "interface.sol", "tokenhelper.sol"):
        dst_path = os.path.join(dst_dir, file)
        if not os.path.exists(dst_path):
            copyfile(data_dir / file, dst_path)

    root_path = os.path.abspath(os.path.join(CACHE_DIR, "result"))
    os.makedirs(root_path, exist_ok=True)
    for file in ("foundry.toml", "remappings.txt"):
        dst_path = os.path.join(root_path, file)
        if not os.path.exists(dst_path):
            copyfile(data_dir / file, dst_path)

    if not os.path.exists(os.path.join(root_path, "lib", "forge-std")):
        run_cmd(["forge", "install", "foundry-rs/forge-std", "--no-commit"])

def extract_code_from_content(content):
    if "```" in content:
        codes = content.split("```")
        
        code = codes[1]
        for lang in ["solidity", "Solidity", "sol"]:
            if code.startswith(lang):
                code = code.lstrip(lang)
        return code

    elif "pragma solidity" in content:
        codes = content.split("pragma solidity")
        
        code = "pragma solidity" + codes[1]
        if "This contract" in code:
            code = code.split("This contract")[0]
        if "Explanation" in code:
            code = code.split("Explanation")[0]
        if "Note that" in code:
            code = code.split("Note that")[0]
        return code

    else:
        return None

def rm_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)

def run_cmd(cmd:List[str], stdout=None, stderr=None):
    try:
        if stdout is None or stderr is None:
            p = Popen(cmd, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)
            p.communicate()
        else:
            rm_file(stdout)
            rm_file(stderr)
            with open(stdout, "w") as out, open(stderr, "w") as err:
                p = Popen(cmd, stdin=PIPE, stdout=out, stderr=err)
                p.communicate()
                
            remove_color_annotations(stdout)
            remove_color_annotations(stderr)

    except Exception as e:
        print(f"Error running command {cmd}: {e}")

def foundry_test_error(test_path):
    with open(test_path,"r") as f:
        log_data = f.read()
        log_data = remove_ansi_escape_sequences(log_data).lower()
        
    if "setup failed" in log_data:
        return "setup failed"
    
    elif "database error" in log_data:
        return "database error"
    
    elif "find(StdStorage): Failed to write value".lower() in log_data:
        return "find(StdStorage): Failed to write value".lower()
    
    elif "could not instantiate forked environment".lower() in log_data:
        return "could not instantiate forked environment".lower()
    
    return None

def read_errors(compile_path, window=5):
    with open(compile_path,"r") as f:
        log_data = f.read()
        log_data = remove_ansi_escape_sequences(log_data)

    error_lines = []
    lines = log_data.split('\n')
    for i, line in enumerate(lines):
        if line.strip().startswith("Error (") or line.strip().startswith("Error: Compiler error "):
            error_block = [line]
            if i + window < len(lines):
                error_block.extend(lines[i + 1: i + window])

            error_lines.append('\n'.join(error_block))

    return "\n".join(error_lines)

def write_code_to_file(code, file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        f.write(code)

def read_code_from_file(file_path):
    assert os.path.exists(file_path), f"File {file_path} does not exist"
    with open(file_path, "r") as f:
        code = f.read()
    return code

def try_import_value(value_name):
    if value_name in os.environ:
        return os.environ[value_name]

    raise ValueError(f"Cannot find value {value_name}")

def request_url(url):
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    proxies = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    try:
        response = requests.get(url, proxies=proxies)
    except Exception:
        response = None
    if response is not None and response.status_code == 200:
        response = json.loads(response.text)['result']
        return response
    return None

def get_func_name(sig):
    if len(sig) == 0 or sig == '0x':
        return f"0x"
    _sig = fetch_sig(sig)
    if _sig is None:
        # print(f"Signature {sig} not found in the database.")
        return f"unknown{sig[2:]}"
    else:
        name = _sig['name']
        return name

def set_os_proxy():
    """Intentionally left as a compatibility hook; requests and Foundry honor
    the standard HTTPS_PROXY environment variable."""

def bytes2hex(b):
    if isinstance(b, bytes):
        return "0x" + b.hex()
    elif isinstance(b, str):
        return b
    elif type(b) in (list, tuple):
        return type(b)(bytes2hex(_) for _ in b)
    else:
        return b

def only_decode(types, data:bytes):
    # if the data is hex number, turn it to bytes
    if isinstance(data, str) and data.startswith("0x"):
        data = bytes.fromhex(data[2:])
    try:
        return decode(types, data)
    except Exception as e:
        # raise e
        return None

def decode_output(sig, output):
    name = get_func_name(sig)
    if name != "0x" and not name.startswith("unknown"):
        decoded_output = Loader.output_decode(sig, bytes.fromhex(output[2:]) if output.startswith("0x") else bytes.fromhex(output))
        dec_output = bytes2hex(decoded_output)
        if dec_output is not None:
            return dec_output
        return output
    else:
        return output

def decode_abi(sig, input, value="0.0", anyway=False):
    name = get_func_name(sig)
    if name != "0x" and not name.startswith("unknown"):
        _, _, values = Loader.abi_decode(sig, bytes.fromhex(input))
        if values is None:
            return f"unknown{sig[2:]}"
        values = bytes2hex(values)
        if not anyway:
            values = type(values)("long param" if isinstance(v, str) and len(v) > 2 + 5*64 else v for v in values)
        return f"{name}{values}"
    
    elif name == "0x":
        if anyway:
            if value != '0.0':
                return f"fallback{{value={value} ether}}({input})"
            
            return f"fallback({input})"
        else:
            return "fallback()"
    
    else:
        if anyway:
            if value != '0.0':
                return f"call{{value={value} ether}}({sig[2:]}{input})"
            return f"call({sig[2:]}{input})"
            return f"unknown{sig[2:]}({input})"
        else:
            return name

def read_json(file_path:str):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    else:
        raise FileNotFoundError(f"File {file_path} does not exist")

def write_json(file_path:str, data:dict):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        if type(data) == str:
            f.write(data)
        else:
            json.dump(data, f)

def read_success_cases(log_path):
    assert os.path.exists(log_path), f"Log file {log_path} does not exist."
    to_vuls = []
    tx_hashes = []
    chains = []

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("bsc") or line.startswith("eth"):
                if "completed" in line.lower():
                    chain, txs = line.strip().split(" ")[0:2]
                    txs = [tx.lower() for tx in txs.strip().split(",")]
                    to_vuls.append(["0"] * len(txs))
                    tx_hashes.append(txs)
                    chains.append(chain)
    return tx_hashes, to_vuls, chains

def rerun_failed_cases(log_path, include_timeout=True):
    assert os.path.exists(log_path), f"Log file {log_path} does not exist."
    to_vuls = []
    tx_hashes = []
    chains = []

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("bsc") or line.startswith("eth"):
                if not "completed" in line.lower():
                    if not include_timeout and "timed out" in line.lower():
                        continue
                    chain, txs = line.strip().split(" ")[0:2]
                    txs = [tx.lower() for tx in txs.strip().split(",")]
                    to_vuls.append(["0"] * len(txs))
                    tx_hashes.append(txs)
                    chains.append(chain)
    return tx_hashes, to_vuls, chains

def read_excludes(dst_dir, CHAINS=["eth", "bsc"]):
    excludes = {"eth": [], "bsc": []}
    for chain in CHAINS:
        if os.path.exists(f"{dst_dir}/{chain}"):
            for tx in os.listdir(f"{dst_dir}/{chain}"):
                excludes[chain].append(tx.strip().lower())
    return excludes
    
def read_benchmark(file_path:str, CHAINS=["eth", "bsc"], date_begin=None, date_end=None, exclude=True):
    """
    Read benchmark transactions from a file.
    """
    assert date_begin is None or isinstance(date_begin, str), "Date must be a string in the format YYYY-MM-DD"
    incidents = []
    dates = []
    tx_hashes = []
    to_vuls = []
    chains = []
    
    if exclude:
        excludes = read_excludes(f"{CACHE_DIR}/result/result_2.0.0_ase_artifacts", CHAINS)
        
        
    df = pd.read_csv(file_path)
    
    attacks = df[(~df['Attack Tx'].isna())]

    attacks['Date'] = pd.to_datetime(attacks['Date'], format='%Y/%m/%d')
    if date_begin is not None:
        attacks = attacks[attacks['Date'] >= pd.Timestamp(date_begin)]
    
    if date_end is not None:
        attacks = attacks[attacks['Date'] <= pd.Timestamp(date_end)]
    
    n_exclueds = 0
    
    for incident, date, chain, _txs, _to_vuls in zip(attacks['Incidents'].tolist(), attacks['Date'].tolist(), attacks['Chain'].tolist(), attacks['Attack Tx'].tolist(), attacks['ToVuls'].tolist()):
        txs = [tx.strip().split("?")[0].split("/")[-1].lower() for tx in re.split(";|,", _txs.strip())]
        if str(_to_vuls) == "nan":
            to_vul = ["0"] * len(txs)
        else:
            to_vul = [v.strip().split(".")[0] for v in re.split(";|,", str(_to_vuls).strip())]
            assert len(to_vul) == len(txs), f"Length of ToVuls {len(to_vul)} does not match length of txs {len(txs)}"

        chain = chain.strip().lower()
        if chain not in CHAINS or len(txs) == 0:
            continue
        
        if exclude and chain in excludes and txs[0] in excludes[chain]:
            n_exclueds += 1
            continue
        incidents.append(incident)
        # reformat date to YYYY/MM/DD
        dates.append(date.strftime('%Y/%m/%d'))
        tx_hashes.append(txs)
        to_vuls.append(to_vul)
        chains.append(chain)
        
        # for tx in txs:
        #     tx = tx.strip().split("?")[0].split("/")[-1].lower()
        #     if f"{chain}-{tx}" not in uniques:
        #         tx_hashes.append(tx)
        #         chains.append(chain)
        #         uniques.add(f"{chain}-{tx}")
    print(f"Excluding {n_exclueds} incidents from {file_path}.")
    
    return incidents, dates, tx_hashes, to_vuls, chains

dst_dir = ".tracexp_cache"

def rm_trace(tx_hash, chain, tracer=None):
    if tracer is None:
        trace_path = f"{dst_dir}/tx_full/{chain}/{tx_hash}.json"
    else:
        tracer_name = os.path.basename(tracer)
        trace_path = f"{dst_dir}/tx_{tracer_name.split('.')[0]}/{chain}/{tx_hash}.json"
    
    # remove the file if it is empty
    if os.path.exists(trace_path) and os.path.getsize(trace_path) == 0:
        os.remove(trace_path)
        print(f"Removed empty trace for {tx_hash} at {trace_path}")
        return
    
def get_existing_interfaces(interface_path=f"{DST_DIR}/bsc/interface.sol"):
    """match all the `interface Ixxxx {`"""
    if not os.path.exists(interface_path):
        return []
    
    with open(interface_path, "r") as f:
        content = f.read()
    
    interfaces = re.findall(r"interface\s+(\w+)\s*{[^}]*}", content, flags=re.DOTALL)
    return interfaces

def get_attack_pattern(result_path, model="gpt-5"):
    records_path = f"{result_path}/records.json"
    with_new_contract = False
    with_callback = False
    with_delegate_calls = False
    if os.path.exists(records_path):
        records = read_json(records_path)
        with_new_contract = records.get("with_new_contract", False)
        with_callback = records.get("with_callback", False)
        with_delegate_calls = records.get("with_delegate_calls", False)
    return {"with_new_contract": with_new_contract, 
            "with_callback": with_callback, 
            "with_delegate_calls": with_delegate_calls}

def get_valid_code(result_path, model="gpt-5"):
    records_path = f"{result_path}/records.json"
    # assert os.path.exists(records_path)
    if not os.path.exists(records_path):
        return -1
    records = read_json(records_path)
    
    if "efg_node_count" not in records:
        return 0
    
    elif len(records.get("sys_prompt", "")) == 0 or len(records.get("user_prompt", "")) == 0:
        return 1
            
    elif records.get(f"synthesis_status_{model}", -1) != 1:
        return 2

    elif records.get(f"syntax_status_{model}", -1) != 1:
        return 3
    
    elif (records.get(f"reflection_consistency_{model}", False) and records.get(f"reflection_iterations_{model}", -1) == 0) or \
        (records.get(f"semantic_wo_reflection_consistency_{model}", False) and records.get(f"semantic_wo_reflection_iterations_{model}", -1) == 0):
        return 4
    
    elif records.get(f"reflection_consistency_{model}", False) and records.get(f"reflection_iterations_{model}", -1) > 0:
        return 5

    elif (records.get(f"semantic_wo_reflection_consistency_{model}", False) and records.get(f"semantic_wo_reflection_iterations_{model}", -1) > 0) or \
            (records.get(f"semantic_w_reflection_consistency_{model}", False) and records.get(f"semantic_w_reflection_iterations_{model}", -1) > 0) or \
                (records.get(f"semantic_status_{model}", False)):
        return 6

    else:
        return -1