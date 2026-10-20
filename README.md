# TracExp

TracExp is a research prototype for automated exploit synthesis from on-chain attack transactions. Given a transaction hash, it reconstructs a contract-centric execution flow graph, localizes the attack-relevant call path, lifts the execution trace into compact semantic IR, and uses an LLM to synthesize and iteratively refine a Foundry PoC.

## Relationship to Panoramix / DiSCo

TracExp is built on top of the Panoramix EVM decompiler distributed in the [DiSCo](https://github.com/b1ue3ky/disco) repository. DiSCo supplies the underlying loader, bytecode lifter, semantic settings, and signature database used by TracExp; TracExp adds attack-transaction tracing, attack-scope localization, trace-driven compression, PoC synthesis, syntax and semantic refinement.

## Features

- Extract contract-centric execution flow graphs and token/oracle information from transaction hashes.
- Identify attack patterns and select the critical trace paths.
- Reuse Panoramix/DiSCo trace lifter and loop compression to obtain compact semantic IR.
- Generate Foundry test code with an OpenRouter-compatible LLM endpoint.
- Iteratively repair compilation errors, execute against forks, and refine semantic differences.
- Include offline static-analysis mode for tracing and IR generation without LLM calls.

## Installation

### System prerequisites

- Python 3.10 or newer
- [Foundry](https://book.getfoundry.sh/) (`forge`, `cast`, and `anvil`) for compiling and executing PoCs
- RPC endpoints with `debug_traceTransaction` support
- A web3 provider configured through `ETH_RPC_URL` or `BSC_RPC_URL`

> **Important:** TracExp requires an RPC endpoint that can return transaction traces, such as the node's `trace_transaction` API; this generally requires an archive-synced node. As an alternative strategy, [Anvil](https://www.getfoundry.sh/anvil) can simulate the target transaction while [Alchemy](https://dashboard.alchemy.com/) or another provider is used to query specific historical state, allowing comparable trace data to be collected.

### Python package

```bash
git clone https://github.com/b1ue3ky/TracExp.git
cd TracExp
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Alternatively, `pip install -e .` also installs the DiSCo dependency through its Git URL. If you prefer to use a local DiSCo checkout, install that checkout first and then install TracExp.

### Foundry workspace

The first run creates a portable Foundry workspace under `.tracexp_cache/result/`, copies TracExp's `basetest.sol`, `interface.sol`, `tokenhelper.sol`, `foundry.toml`, and `remappings.txt`, and attempts to install `forge-std`. If the automatic installation is blocked by your network, run `forge install foundry-rs/forge-std --no-commit` inside that workspace.

## Configuration

Copy `.env.example` to `.env` and fill in the values you need:

```bash
cp .env.example .env
```

Required variables for online analysis are the RPC endpoints and Etherscan key. Required variables for LLM synthesis are the OpenRouter-compatible endpoint and API key. Static-only analysis does not call the LLM. The cache directory defaults to `.tracexp_cache`; override it with `TRACEXP_CACHE_DIR`.

## Usage

### Static tracing and IR analysis

```bash
python -m tracexp \
  --chain eth \
  --tx-hashes 0xYOUR_TX_HASH \
  --only-static
```

This mode traces the transaction, localizes the attack path, lifts and compresses the trace, and writes records and prompts without invoking the LLM.

### Full PoC synthesis

```bash
python -m tracexp \
  --chain eth \
  --tx-hashes 0xYOUR_TX_HASH \
  --llm-client gpt-5
```

For multiple related transactions, pass them together and indicate whether each transaction targets the vulnerable contract:

```bash
python -m tracexp \
  --chain eth \
  --tx-hashes 0xTX_1 0xTX_2 \
  --to-vuls 0 1 \
  --llm-client gpt-5
```

### Common options

| Option | Description |
|---|---|
| `--chain eth\|bsc` | Chain to analyze. |
| `--tx-hashes HASH...` | One or more transaction hashes. |
| `--to-vuls 0\|1...` | Whether each transaction is sent to the vulnerable contract. |
| `--attacker ADDRESS` | Attacker or beneficiary address; defaults to the transaction sender. |
| `--only-static` | Trace and analyze without LLM synthesis. |
| `--only-synthesizer` | Synthesize from cached analysis records. |
| `--no-refine` | Skip all post-synthesis refinement. |
| `--no-reflection` | Skip self-reflection refinement. |
| `--no-semantic-refine` | Skip semantic-difference refinement. |
| `--ablation-study 1\|2` | Disable concrete-value tracking or trace compression. |
| `--syntax-iters N` | Maximum syntax repair iterations. |
| `--semantic-iters N` | Maximum semantic repair iterations. |

## Output layout

Results are stored under the cache directory:

```text
.tracexp_cache/
└── result/
    └── result_1.0.1/
        └── eth/
            └── 0xYOUR_TX_HASH/
                ├── records.json
                ├── sys_prompt.txt
                ├── user_prompt.txt
                ├── syn_code_gpt-5.sol
                ├── syn_code_gpt-5_syntax_refined.sol
                └── syn_code_gpt-5_semantic_refined.sol
```

The exact refined-file names depend on the selected model, iteration counts, and flags. `records.json` contains timings, attack-pattern metadata, prompt artifacts, LLM status, and validation status.

## Repository layout

```text
tracexp/          Core Python package
tracexp/tracer/   Custom EVM debug tracers
tracexp/data/     Foundry helper contracts and configuration
templates/        Prompt and PoC templates
```

## Security and responsible use

TracExp analyzes historical exploits and reconstructs them for research, incident response, and defensive evaluation. The generated code can execute arbitrary contract calls against a forked chain. Review every synthesized PoC before execution, prefer local forks, and never point generated code at production systems or systems you are not authorized to test.

## License

This project is released under the [MIT License](LICENSE). The bundled Foundry helper files and generated interface declarations are provided for research use; third-party dependencies remain under their own licenses.
