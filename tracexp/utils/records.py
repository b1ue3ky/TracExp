import os
import json
import time
import pandas as pd

from .helpers import DST_DIR, CACHE_DIR

class Records:
    """
    A class to record and print records for experiments.
    """

    def __init__(self, file_path):
        self.run_start_time = None
        self.run_end_time = None
        
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                self.records = json.load(f)
        else:
            self.records = {}
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        self.file_path = file_path

    def measure_time(self, name):
        return _Timer(self, name)
    
    def get_record(self, name, default=None, dst_dir=DST_DIR):
        """
        Get the value of a record by its name.
        """
        if name == "callgraph":
            callgraph_path = os.path.join(os.path.dirname(self.file_path), f"callgraph.json")
            if os.path.exists(callgraph_path):
                with open(callgraph_path, "r") as f:
                    return json.load(f)
            else:
                return default
            
        if "code_path" in name:
            rel_path = self.records.get(name, None)
            if rel_path is not None:
                return f"{dst_dir}/{rel_path}"
            else:
                return default
        return self.records.get(name, default)
    
    def has_record(self, name):
        """
        Check if a record with the given name exists.
        """
        if name == "callgraph":
            callgraph_path = os.path.join(os.path.dirname(self.file_path), f"callgraph.json")
            return os.path.exists(callgraph_path)
        
        return name in self.records
    
    def add_record(self, name, value):
        """
        Add a record with a given name and value.
        """
        if name == "callgraph":
            callgraph_path = os.path.join(os.path.dirname(self.file_path), f"callgraph.json")
            with open(callgraph_path, "w") as f:
                json.dump(value, f, indent=4)
            return
        
        if "code_path" in name:
            if value is not None:
                if value.startswith(CACHE_DIR):
                    paths = value.split("/")
                    if len(paths) == 5:
                        value = f"{paths[-3]}/{paths[-2]}/{paths[-1]}"
            else:
                self.records[name] = None
        
        self.records[name] = value
        self.save(slient=True)

    def printed(self, name, value):
        if name.startswith("time"):
            return True
        if "status" in name:
            return True
        if "code_path" in name:
            return True
        if name == "user_prompt":
            return True
        return False

    def summary(self):
        print("\n--- Metrics Summary ---")
        for name, value in self.records.items():
            if self.printed(name, value):
                print(f"{name}: {value}")
    
    def save_record(self, record, suffix=""):
        with open(f"{self.file_path.replace('.json', '')}_{record}{suffix}.txt", "w") as f:
            f.write(self.records[record])
    
    def record_metrics(self, result:dict):
        if "callgraph" in result:
            callgraph_path = os.path.join(os.path.dirname(self.file_path), f"callgraph.json")
            with open(callgraph_path, "w") as f:
                json.dump(result["callgraph"], f, indent=4)
            del result["callgraph"]
        
        r = {}
        for k, v in result.items():
            if "code_path" in k and v is not None:
                if v.startswith(CACHE_DIR):
                    paths = v.split("/")
                    if len(paths) == 6:
                        r[k] = f"{paths[-3]}/{paths[-2]}/{paths[-1]}"
                    else:
                        r[k] = v
                else:
                    r[k] = v
            else:
                r[k] = v    
        
        self.records.update(r)
        self.save(slient=True)
    
    def to_csv_keys(self, key, value):
        if type(value) in [int, float]:
            return True
                
        return False
    
    def save(self, also_to_csv:bool=True, slient:bool=False):
        """
        Save the records to a JSON file.
        """
        with open(self.file_path, "w") as f:
            json.dump(self.records, f, indent=4)
        
        if also_to_csv:
            csv_path = self.file_path.replace(".json", ".csv")
            df = pd.DataFrame([{k:v for k, v in self.records.items() if self.to_csv_keys(k, v)}])
            df.to_csv(csv_path, index=False)
        if not slient:
            print(f"Metrics saved to {self.file_path}")

    def load(self):
        """
        Load records from a JSON file.
        """
        with open(self.file_path, "r") as f:
            self.records = json.load(f)
        print(f"Metrics loaded from {self.file_path}")
        
class _Timer:
    def __init__(self, records, name):
        self.records = records
        self.name = f"time_{name}"

    def __enter__(self):
        self.start_time = time.monotonic()

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.monotonic() - self.start_time
        self.records.add_record(self.name, elapsed)