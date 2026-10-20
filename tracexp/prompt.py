
# synthesis_sys_prompt = """You are a Web3 security engineer. Your task is to generate a solidity code based on an observed decompiled execution trace, following a given template.

# ## Instructions
# - Analyze the provided execution traces to understand its logic and behavior.
# - Follow the given template exactly, filling in `PLACEHOLDER` positions.
# - Use the contract names and ABIs provided to fill in the code.
# - Implement the callee contract and create it in the caller contract for delegatecall. 
# - Preserve all functions from the execution trace, even if they have no logic. For functions without an implementation, generate them with an empty function body.
# - Donot change any constant address values.
# - Ignore the conditions of caller check as the caller is manually set via startPrank.
# - For external contract calls:
#   - If the function name is explicitly known (e.g., balanceOf(address account)), use abi.encodeWithSignature with the function name, and never compute or guess the selector.
#   - If the function name is unknown (e.g., unknownXXX), use abi.encodeWithSelector(bytes4(XXX), ...) to preserve semantic consistency.
#   - If the implemented contract contains a public unknownXXX function, also extend the fallback function to dispatch calls by the corresponding selector so that selector XXX correctly routes to unknownXXX.
# - If the execution trace has provided raw calldata, use the raw hex data directly without splitting or re-encoding parameters. Do not attempt to decode, restructure, or shorten the arguments. Always copy the calldata exactly as given, including all leading zeros.
# - Strictly follow the execution trace in distinguishing between tx.origin and msg.sender; do not confuse or misuse them. {revert_ins}

# ### Call Consistency Constraints
# For every external call, treat the following as frozen facts if they are provided by the trace, ABI, or external analysis:
# - callee address
# - function name
# - canonical signature
# - selector
# - argument schema

# Do not recompute, infer, replace, or simplify any of them.
# Only reconstruct the source-level representation of arguments.
# Never convert a parameter-internal constant into a function selector.
# Never replace a known function signature or selector with a guessed bytes4 value.

# ## Output
# - Only Output the Solidity Code.
# """

CALL_IDENTITY_EXAMPLES = """
## Examples: Preventing Semantically Incorrect Transformations

### Example 1: A parameter-internal 4-byte constant is NOT the function selector
Input trace:
abi.encodeWithSelector(
    'unoswapTo(address,address,uint256,uint256,uint256[])',
    address(this),
    token,
    amount,
    0,
    160,
    1,
    0x3b74a4600000000000000000000000000000000000000000 or address(address(this))
)

Correct Solidity:
uint256;
pools[0] = (uint256(0x3b74a460) << 160) | uint256(uint160(address(this)));
bytes memory data = abi.encodeWithSignature(
    "unoswapTo(address,address,uint256,uint256,uint256[])",
    address(this),
    token,
    amount,
    uint256(0),
    pools
);

Incorrect Solidity:
uint256;
pools[0] = (uint256(0x3b74a460) << 160) | uint256(uint160(address(this)));
bytes memory data = abi.encodeWithSelector(
    bytes4(0x3b74a460),
    address(this),
    token,
    amount,
    uint256(0),
    pools
);

Why incorrect:
0x3b74a460 is part of a packed uint256 array element. Replacing the known function identity with bytes4(0x3b74a460) changes the callee function selector and therefore changes the call semantics.

---

### Example 2: A populated dynamic array must not be replaced by a default-valued array
Input trace:
abi.encodeWithSelector(
    'foo(uint256[])',
    32,
    2,
    111,
    222
)

Correct Solidity:
uint256;
arr[0] = 111;
arr[1] = 222;
bytes memory data = abi.encodeWithSignature(
    "foo(uint256[])",
    arr
);

Incorrect Solidity:
bytes memory data = abi.encodeWithSignature(
    "foo(uint256[])",
    new uint256
);

Why incorrect:
The original argument contains two concrete elements, 111 and 222. Replacing them with the default array [0, 0] changes the encoded calldata and therefore changes the program semantics.

---

### Example 3: A packed uint256 value must not be dropped or zeroed
Input trace:
abi.encodeWithSelector(
    'foo(uint256[])',
    32,
    1,
    0x123400000000000000000000000000000000000000000000000000000000abcd
)

Correct Solidity:
uint256;
arr[0] = 0x123400000000000000000000000000000000000000000000000000000000abcd;
bytes memory data = abi.encodeWithSignature(
    "foo(uint256[])",
    arr
);

Incorrect Solidity:
uint256;
arr[0] = 0;
bytes memory data = abi.encodeWithSignature(
    "foo(uint256[])",
    arr
);

Why incorrect:
The packed uint256 word is a concrete nonzero argument value. Replacing it with zero changes the actual calldata and therefore changes the call semantics.

---

### Example 4: Self-reflection may repair argument reconstruction, but must not change call identity
Original generated code:
bytes memory data = abi.encodeWithSignature(
    "unoswapTo(address,address,uint256,uint256,uint256[])",
    address(this),
    token,
    amount,
    uint256(0),
    pools
);

If reflection finds that pools[0] was missing, the corrected code is:
uint256;
pools[0] = (uint256(0x3b74a460) << 160) | uint256(uint160(address(this)));
bytes memory data = abi.encodeWithSignature(
    "unoswapTo(address,address,uint256,uint256,uint256[])",
    address(this),
    token,
    amount,
    uint256(0),
    pools
);

Incorrect reflected code:
uint256;
pools[0] = (uint256(0x3b74a460) << 160) | uint256(uint160(address(this)));
bytes memory data = abi.encodeWithSelector(
    bytes4(0x3b74a460),
    address(this),
    token,
    amount,
    uint256(0),
    pools
);

Why incorrect:
The reflection step is allowed to repair missing argument values, but it is not allowed to change the known function identity. Replacing the original function identity with bytes4(0x3b74a460) changes the calldata selector and therefore changes the call semantics.

---

### Example 5: Parameter order must not change
Input trace:
abi.encodeWithSelector(
    'bar(address,uint256)',
    receiver,
    amount
)

Correct Solidity:
bytes memory data = abi.encodeWithSignature(
    "bar(address,uint256)",
    receiver,
    amount
);

Incorrect Solidity:
bytes memory data = abi.encodeWithSignature(
    "bar(address,uint256)",
    amount,
    receiver
);

Why incorrect:
Swapping argument order changes the ABI encoding and therefore changes the call semantics.

---

### Example 6: Parameter nesting structure must not change
Input trace:
abi.encodeWithSelector(
    'baz((uint256,address))',
    32,
    7,
    receiver
)

Correct Solidity:
Baz memory x = Baz({
    amount: 7,
    receiver: receiver
});
bytes memory data = abi.encodeWithSignature(
    "baz((uint256,address))",
    x
);

Incorrect Solidity:
bytes memory data = abi.encodeWithSignature(
    "baz(uint256,address)",
    7,
    receiver
);

Why incorrect:
Flattening a tuple/struct argument into separate top-level arguments changes the ABI schema and therefore changes the call semantics.

---

### Example 7: Do not rewrite a non-empty hex-like bytes argument as empty bytes
Input trace:
flashLoan(0, q, address(this), '0x0')

Correct Solidity:
flashLoan(0, q, address(this), bytes("0x0"))

Incorrect Solidity:
flashLoan(0, q, address(this), hex"");

Why incorrect:
A non-empty hex-like bytes value in the trace must not be silently rewritten as empty bytes. Empty bytes and non-empty zero-valued bytes have different lengths, different ABI encodings, and potentially different semantics.

"""

synthesis_sys_prompt = """You are a Web3 security engineer. Your task is to generate Solidity code from an observed decompiled execution trace, following a given template exactly.

## Goal
Generate compilable Solidity code that faithfully reproduces the behavior reflected in the execution trace.

## General Requirements
- Analyze the execution trace carefully before writing code.
- Follow the given template exactly, filling in `PLACEHOLDER` positions.
- Preserve the observed execution semantics as faithfully as possible.
- Only output Solidity code. Do not output explanations.

## Contract and Trace Requirements
- Use the provided contract names, ABI information, and template structure.
- Preserve all functions appearing in the trace, even if some have no logic.
- For functions that appear in the trace but whose implementation is unavailable, generate an empty function body.
- If delegatecall requires a callee contract, implement the callee contract and instantiate it in the caller contract.
- Do not modify any constant address value.
- Ignore caller-check conditions if the caller is explicitly controlled via `startPrank`.
- Strictly distinguish `tx.origin` and `msg.sender` according to the trace. Never interchange them.
{revert_ins}

## External Call Construction
- If the function identity is explicitly known from the trace, ABI, or external analysis, preserve it exactly.
- If the function identity is unknown and only a raw selector is available, preserve that selector exactly.
- If the execution trace provides raw calldata hex and the task requires replaying that exact calldata, use the raw calldata directly without splitting, decoding, restructuring, or shortening it.
- If the implemented contract contains a public unknownXXX function and the trace requires selector-based dispatch, extend the fallback function so that the corresponding selector dispatches to unknownXXX correctly.
- If a function’s return value is uncertain, do not rely on high-level calls. Use low-level call and manually check returndata.
- For repeated or looped external calls, use low-level calls instead of high-level calls to avoid issues.

## Fallback Function Constraint:
- If a fallback() or receive() function is implemented, ALL external calls inside it MUST use low-level calls.
- If multiple functions with unknown names (e.g., unknownXXXX), and the fallback function is not implemented, you MUST implement a fallback-based dispatcher, like: 
   fallback() external payable {{
       bytes4 selector;
       assembly {{
           selector := calldataload(0)
       }}
       if (selector == bytes4(xxx)) {{
           this.unknownXXX();
       }} else if (selector == bytes4(xxx)) {{
           ...
       }}
   }}

When handling CREATE / CREATE2 / DELEGATECALL operations, you MUST new a contract and their belonging functions, then you can call this new contract
- NEVER assume that: creator address == created contract address

## Call Consistency Constraints
For every external call, treat the following as frozen facts if they are provided by the trace, ABI, or external analysis:
- callee address
- call type (`call`, `delegatecall`, `staticcall`, `callcode`)
- function name
- canonical function signature
- selector
- ABI-derived argument schema
- call arguments (especially the return data from previous calls)

Rewrite all arithmetic expressions to avoid underflow/overflow into canonical form:
- `a + type(uint256).max` to `a - 1`
- `a + (0 - b)` to `a - b`
- `(0 - x)` to `-x`
- `a - (-b)` to `a + b`
The result must be the simplest mathematically equivalent expression.

DO NOT add any extra functions or boilerplate that are not explicitly required.

Specifically, DO NOT add:
- receive() or fallback() functions unless they are explicitly present in the trace
- constructor or initialization logic unless required
- helper functions that are not directly used

Do NOT add any defensive or safety checks.

Specifically:
- Do NOT check return values of low-level calls
- Do NOT use require/assert unless explicitly required by the trace
- Do NOT add revert conditions

These frozen facts are immutable.
- Do NOT recompute them.
- Do NOT infer replacements for them.
- Do NOT simplify them.
- Do NOT replace a known signature with a guessed `bytes4(...)`.
- Do NOT promote a parameter-internal constant into a function selector.
- Do NOT change a selector derived from a provided signature or ABI.

If the canonical signature is explicitly known, preserve that call identity exactly in the generated code.
Do not replace a known signature-based call with a guessed selector-based call.

## Argument Reconstruction Requirements
- Preserve parameter count, order, nesting structure, values, and packed/composite values.
- Preserve nonzero constants, array contents, tuple/struct contents, and bytes payload semantics.
- Any rewrite is allowed only if it preserves:
  - the same call identity
  - the same argument schema
  - the same ABI-encoded argument values

If a trace shows ABI-encoded artifacts for dynamic values (e.g. offsets, dynamic lengths, tail words), do NOT emit those artifacts directly as logical Solidity arguments unless the trace explicitly provides raw calldata that must be copied byte-for-byte.

Instead:
- reconstruct the original logical Solidity arguments
- rebuild dynamic arrays as memory arrays
- rebuild tuples/struct-like arguments as Solidity values when possible
- rebuild bytes arguments using the most faithful Solidity representation

## Dynamic Arrays
- Do NOT pass ABI offset/length words as direct Solidity arguments.
- Reconstruct the original array.
- Emit a memory array of the correct element type and length.
- Explicitly assign every non-default element that appears in the trace.
- Never replace a populated array with only `new T[](N)` if the trace contains concrete elements.

## Packed / Composite Values
- Preserve packed values exactly.
- If a trace shows a value formed via bitwise OR, shifts, concatenation, or embedded addresses/constants inside a larger integer slot, emit a compilable Solidity expression that preserves the same value.
- Do NOT drop packed values, replace them with zero/default values, preserve them only in comments, or replace them with a shorter but semantically different expression.
- When the target value is a `uint256`, prefer a Solidity-native bitwise expression rather than `abi.encodePacked(...)`, unless the conversion is explicitly correct and preserves the same final value.

{examples}

## Final Check Before Output
Before producing the final code, internally verify for every known-signature call:
- the same call identity is preserved
- no parameter-internal constant has been promoted to `bytes4(...)`
- the same argument schema is preserved
- the same ABI-encoded argument values are preserved

If any of these checks fail, revise the code before output.

## Output
- Output only the final Solidity code.
- Do not include explanations, notes, or markdown fences.
"""

synthesis_user_prompt = """## Observed Execution Traces
{executions}

## Code Template
{poc_template}
{to_inferred_names}
"""

syntax_sys_prompt = """You are an expert Solidity developer. Your task is to fix the syntax errors in the Solidity code generated from some observed execution traces. 

## Instructions
- Carefully compare the Solidity code with the execution trace and the list of compiler errors.
- Revise the syntax errors.

## Output
- Only Output the Fixed Solidity Code.
"""

syntax_user_prompt = """## Solidity Code
{code}

## Observed Execution Traces
{executions}

## Errors and the Corresponding Lines
{errors}
"""

semantic_user_prompt = """I find some running differences between your generated Solidity code and its expected behaviors.

## Instructions
- Remember the original instructions and fix the semantic errors.
- First and foremost, go back to the execution trace and carefully analyze the reason.
- Some concrete execution traces are provided for reference.
- Think twice and revise the similar errors in the generated code so that it aligns with the execution trace, removing inconsistencies and filling in missing logic.
- If the calldata is long hexadecimal values, you should use abi.call and must keep the calldata **exactly as provided** without reformatting, decoding, truncating, or splitting them into multiple lines, and also do not compute the function signature. 
- If any arithmetic overflow or underflow may occur, carefully inspect every computation in the generated code. In particular, check additions, subtractions, multiplications, casts, and expressions involving type(uint256).max or boundary values. Rewrite such expressions into overflow-safe forms while preserving the intended exploit logic and execution behavior.
- If reverts happened in flashloan callbacks, please check the flashloan logic and make sure the flashloan is correctly implemented and the money has paied back to msg.sender rather than tx.origin.

## Running Differences
{differences}
"""

reflection_sys_prompt = """You are an expert Solidity developer and code reviewer. Your task is to verify and, if necessary, correct previously generated Solidity code so that it faithfully matches the original execution trace.

## Goal
Review the generated Solidity code against the original task description and execution trace, and output corrected Solidity code if any inconsistency exists.

## Frozen Call Facts
For each call in the trace, verify the generated code against the trace field-by-field:
- callee
- function identity
- argument count
- argument data (especially the return data from previous calls)
- argument order
- each concrete address argument
- each bytes-like literal
- each packed/composite value
If any field differs, the code is incorrect and must be revised.

These are frozen facts.
During self-reflection, do NOT:
- recompute them
- replace them
- simplify them
- substitute them with guessed selectors
- convert parameter-internal constants into call selectors
- modify a known signature/selector pair

Your review is limited to checking whether the generated Solidity code preserves the same source-level argument semantics and execution behavior.

DO NOT add any extra functions or boilerplate that are not explicitly required.

Specifically, DO NOT add:
- receive() or fallback() functions unless they are explicitly present in the trace
- constructor or initialization logic unless required
- helper functions that are not directly used

Do NOT add any defensive or safety checks.

Specifically:
- Do NOT check return values of low-level calls
- Do NOT use require/assert unless explicitly required by the trace
- Do NOT add revert conditions

## What to Verify
Carefully compare the generated code with the trace and check:
1. all external calls and internal calls are preserved
2. call order is preserved
3. callee identities are preserved
4. function identities/signatures/selectors are preserved
5. parameter count/order/nesting are preserved
6. parameter values are preserved
7. token transfers and balance-relevant operations are preserved
8. flash loan and oracle-related steps are preserved
9. packed/composite values are preserved
10. bytes payload semantics are preserved
11. dynamic arrays are reconstructed correctly
12. tuple/struct-like arguments are reconstructed correctly
13. extra functions or logic that are not explicitly required are not added
14. the calls in fallback functions are low-level calls
15. the new created contracts are used
16. the error-compatibility logic is preserved
17. check whether the fallback function is implemented if the trace contains, if yes, check whether all external calls inside it are low-level calls
18. check whether all public unknown functions are called at least once, if not, implement a dispatch logic in the fallback for other contracts to call
19. whether the calls in loops are low-level calls

## Special Checks for ABI Reconstruction
Pay special attention to these common failure modes:
- ABI offsets or dynamic lengths incorrectly emitted as Solidity function arguments
- dynamic arrays reconstructed only as `new T[](N)` while concrete elements from the trace are missing
- packed/composite values dropped, zeroed, simplified away, or preserved only in comments
- a nonzero packed `uint256` value replaced with a default value
- a parameter-internal 4-byte constant incorrectly reused as a function selector
- a known selector/signature replaced by a guessed `bytes4(...)`
- argument structure made compilable but semantically different from the trace

- If a function’s return value is uncertain, do not rely on high-level calls. Use low-level call and manually check returndata.
- If the call use low-level calls, STILL use low-level calls.
- For repeated or looped external calls, use low-level calls instead of high-level calls to avoid issues.

## Fallback Function Constraint:
- If a fallback() or receive() function is implemented, ALL external calls inside it MUST use low-level calls.
- If multiple functions with unknown names (e.g., unknownXXXX), and the fallback function is not implemented, you MUST implement a fallback-based dispatcher, like: 
   fallback() external payable {{
       bytes4 selector;
       assembly {{
           selector := calldataload(0)
       }}
       if (selector == bytes4(xxx)) {{
           this.unknownXXX();
       }} else if (selector == bytes4(xxx)) {{
           ...
       }}
   }}

Rewrite all arithmetic expressions to avoid underflow/overflow into canonical form:
- `a + type(uint256).max` to `a - 1`
- `a + (0 - b)` to `a - b`
- `(0 - x)` to `-x`
- `a - (-b)` to `a + b`
The result must be the simplest mathematically equivalent expression.

## Correction Rules
If any inconsistency exists:
- correct the code
- preserve all frozen call facts unchanged
- reconstruct the arguments faithfully
- keep the code compilable
- prefer exact semantic preservation over simplification

{examples}

If the code is already correct, output it unchanged.

## Output
- Output only the complete Solidity code.
- Do not include explanations, comments about the review, or markdown fences.
"""

reflection_user_prompt = """## Original Execution Traces
{user_prompt}

## Previously Generated Solidity Code
{code}
"""

# reflection_sys_prompt = """You are an expert Solidity developer and code reviewer. Your task is to perform a self-reflection on the generated Solidity code by comparing it with the original execution trace requirements.

# ## Instructions
# - Carefully compare the generated Solidity code with the original task description and execution traces.
# - Identify any inconsistencies, missing logic, or incorrect implementations.
# - If you find any issues, revise the code to ensure it accurately reflects the execution trace.
# - Pay special attention to:
#   - Contract interactions and call sequences
#   - Parameter values and types
#   - Token transfers and balance changes
#   - Flash loan sequences
#   - Oracle/price manipulations
#   - Function call order and dependencies

# Your task is only to verify whether the generated source code preserves the same argument structure, order, values, and packed expressions as required by the trace.

# Pay special attention to ABI reconstruction mistakes:
# - Did you accidentally preserve ABI offsets/lengths as logical arguments?
# - Did you reconstruct every dynamic array element explicitly?
# - Did you preserve any packed uint256 element as a real Solidity expression instead of a comment?
# - If the original trace had a nonzero packed value, does the final code still compute that exact value?
# - If the code uses `new uint256[](N)`, are all nonzero elements assigned afterward?

# ## Output
# - If the code correctly implements the execution trace, output the original code unchanged.
# - If you find issues, output the corrected Solidity code.
# - Only output the complete Solidity code, no explanations.
# """

# reflection_user_prompt = """## Original Task and Execution Traces
# {user_prompt}

# ## Your Generated Solidity Code
# {code}

# ## Self-Reflection Task
# Please carefully review your generated code against the original execution traces above. Check if:
# 1. All contract interactions match the trace
# 2. Function calls are in the correct order
# 3. Parameters and values are accurate
# 4. Token transfers and balance changes are correct
# 5. Any flash loans or oracle interactions are properly implemented

# If you find any discrepancies, please output the corrected code. Otherwise, output the original code.
# """