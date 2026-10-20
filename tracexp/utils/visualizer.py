import graphviz

from panoramix.utils.supplement import fetch_sig
from panoramix.utils.helpers import get_pc, opcode, get_hooked

from panoramix.prettify import trace_to_str

def fetch_name(input):
    sig = input[:10]
    name = fetch_sig(sig)
    return name['name'] if name else sig

def visualize_cfg(blocks, edges, entry_pc, loop_info=None):
    G = graphviz.Digraph('CFG')
    G.attr(rankdir='TB', size='14,10', dpi='300')
    G.attr('node', shape='box', style='filled', fontname='Courier', fontsize='10')
    G.attr('edge', fontname='Arial', fontsize='9')

    def format_while_statement(while_stmt):
        if len(while_stmt) >= 3:
            cond = while_stmt[1]
            body_preview = f"{len(while_stmt[2])} statements" if while_stmt[2] else "empty"
            return f"while {cond}:\\n  {body_preview}"
        return "while (...)"

    # Add nodes.
    for pc, block in blocks.items():
        label = f"PC: {pc}\\n"
        color = 'lightgreen' if pc == entry_pc else 'lightyellow'

        for inst in block:
            inst_str = trace_to_str([inst])
            label += inst_str.replace('\n', '\\n') + "\\n"

        G.node(str(pc), label=label, fillcolor=color)

    for from_pc, targets in edges.items():
        for to_pc, condition in targets:
            G.edge(str(from_pc), str(to_pc), label=str(condition))

    return G

def visualize_call_graph(graph, wo_static=True, attack_scope=None, victim_scope=None, max_width=5, max_depth=5):
    """Visualize the call tree produced by build_calltree_from_efg.

    `graph` is the calltree root node:
        {"contract", "call", "input", "depth", "value", "children": [...], ...}

    Nodes in attack_scope are coloured pink; nodes in victim_scope are blue.
    attack_scope / victim_scope are lists of (contract, composite_input_key) pairs
    where composite_input_key = "{depth}_{call}_{calldata}_{eth_value}".
    """
    G = graphviz.Digraph()

    attack_scope = set(attack_scope) if attack_scope else set()
    victim_scope  = set(victim_scope)  if victim_scope  else set()

    G.attr(rankdir='TB', size='16,12', dpi='300')
    G.attr('node', shape='box', style='filled,rounded', fontname='Comic Sans MS', fontsize='10')
    G.attr('edge', fontname='Comic Sans MS', fontsize='9')

    G.node("node_0", label="User\\n(D0)", fillcolor='lightgreen')

    node_counter = 1

    def _input_key(node):
        v = node.get('value')
        eth_value = int(v or '0') / 1e18
        return f"{node['depth']}_{node['call']}_{node['input']}_{eth_value}"

    def _visit(node, parent_id=None, sibling_idx=1):
        nonlocal node_counter

        depth     = node['depth']
        contract  = node['contract']
        calltype  = node['call']
        raw_input = node.get('input') or ''

        if depth > max_depth:
            return

        current_id = f"node_{node_counter}"
        node_counter += 1

        # ---- node label / colour ----
        if sibling_idx < max_width:
            short = f"{contract[:6]}...{contract[-4:]}" if len(contract) > 10 else contract
            key   = _input_key(node)
            if (contract, key) in attack_scope:
                color = 'lightpink'
            elif (contract, key) in victim_scope:
                color = 'lightblue'
            else:
                color = 'white'

            node_label = f"{short}\\n(D{depth})"
            if "call" in calltype.lower() and len(raw_input) >= 10:
                node_label += f"\\n{fetch_name(raw_input)}"
        else:
            # Too many siblings — show a single "…" placeholder and stop.
            node_label = "..."
            color = 'white'

        G.node(current_id, label=node_label, fillcolor=color)

        if parent_id is not None:
            G.edge(parent_id, current_id, label=f"D{depth}\\n{calltype}")

        if sibling_idx >= max_width:
            return  # don't recurse into the placeholder node

        # ---- recurse into children ----
        children = node.get('children', [])
        if wo_static:
            children = [c for c in children if c['call'] != 'STATICCALL']
        if len(children) > max_width:
            children = children[:max_width]

        for idx, child in enumerate(children):
            _visit(child, parent_id=current_id, sibling_idx=idx + 1)

        return current_id

    _visit(graph)
    # node_1 is always the root call node created by the first _visit call
    G.edge("node_0", "node_1", label=f"D0\\n{graph['call']}")

    return G
