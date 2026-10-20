import os
import subprocess

from web3 import Web3

from tracexp.utils import (build_provider, build_web3, get_endpoint_uri, read_json,
                       write_json, CACHE_DIR)

def get_tracer(tracer_path:str):
    if tracer_path and os.path.exists(tracer_path):
        return open(tracer_path).read()
    else:
        assert tracer_path is not None, "Tracer path cannot be None"

def dumps_trace(trace, file_path, include_pp:bool=False):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        for line in trace:
            pc, opname = line['pc'], line['opName']
            value = None
            
            if opname.startswith("PUSH"):
                value = line['pushes'][-1]
                if isinstance(value, str):
                    if not value.startswith("0x"):
                        value = "0x" + value
                    value = int(value, 16)
                elif isinstance(value, int):
                    pass
            
            if include_pp:
                pops = line.get('pops', [])
                pops = ",".join(str(int(p, 16)) for p in pops)
                pushes = line.get('pushes', [])
                pushes = ",".join(str(int(p, 16)) for p in pushes)
                if value:
                    f.write(f"{hex(pc)}: {opname} {value} [{pops}] [{pushes}]\n")
                else:
                    f.write(f"{hex(pc)}: {opname} [{pops}] [{pushes}]\n")
            else:
                if value:
                    f.write(f"{hex(pc)}: {opname} {value}\n")
                else:
                    f.write(f"{hex(pc)}: {opname}\n")

def trace_exist(chain, tx_hash, tracer="efgTracer"):
    if tracer is not None:
        tracer_name = os.path.basename(tracer)
        trace_saved_path = f"{CACHE_DIR}/tx_{tracer_name.split('.')[0]}/{chain}/{tx_hash}.json"
    else:
        trace_saved_path = f"{CACHE_DIR}/tx_full/{chain}/{tx_hash}.json"
    
    def read_trace(trace_path):
        try:
            trace = read_json(trace_path)
            result = trace.get('result', trace)
            assert result is not None, "Trace result should not be None"
            if 'efg' in result:
                return result['efg']
            elif 'tokenflows' in result:
                return result['tokenflows']
            return None
        except Exception as e:
            return None
    
    return os.path.exists(trace_saved_path) and read_trace(trace_saved_path) is not None

def trace_from_tx_hash(chain, tx_hash, tracer="efgTracer", force=False, read_cache=True):
    # assert tracer is None or tracer == "efgTracer"
    if tracer is not None:
        tracer_name = os.path.basename(tracer)
        trace_saved_path = f"{CACHE_DIR}/tx_{tracer_name.split('.')[0]}/{chain}/{tx_hash}.json"
    else:
        trace_saved_path = f"{CACHE_DIR}/tx_full/{chain}/{tx_hash}.json"

    os.makedirs(os.path.dirname(trace_saved_path), exist_ok=True)
    
    if not force and (os.path.exists(trace_saved_path) or read_cache):
        # print(f"Trace of {tx_hash} already exists at {trace_saved_path}")

        try:
            trace = read_json(trace_saved_path)
            
            result = trace.get('result', trace)
            assert result is not None, "Trace result should not be None"
            if 'efg' in result:
                return result['efg']
            elif 'tokenflows' in result:
                return result['tokenflows']
        except Exception as e:
            if read_cache:
                return None
            else:
                pass 
                       
    if tracer is None:
        endpoint = get_endpoint_uri(chain)
        cmd = f"""curl {endpoint} -X -POST --data '{{"jsonrpc":"2.0","method":"debug_traceTransaction","params":["{tx_hash}",{{}}]}}' -H "Content-Type: application/json" > {trace_saved_path}"""
        subprocess.run(cmd, shell=True)
    
    else:
        if tracer == "oracleTracer":
            tracer = "tracexp/tracer/oracle_tracer.js"
        elif tracer == "efgTracer":
            tracer = "tracexp/tracer/efg_tracer.js"
        else:
            tracer = None
        w3 = build_web3(build_provider(get_endpoint_uri(chain)))
        trace = w3.manager.request_blocking(
            "debug_traceTransaction",
            [tx_hash, {"tracer": get_tracer(tracer)}]
        )
        write_json(trace_saved_path, Web3.to_json(trace))

    print(f"Trace of {tx_hash} saved to {trace_saved_path}")
    trace = read_json(trace_saved_path)

    result = trace.get('result', trace)
    if 'efg' in result:
        return result['efg']
    elif 'tokenflows' in result:
        return result['tokenflows']

    assert False, f"Cannot find trace result in {trace_saved_path}"
    
    return None