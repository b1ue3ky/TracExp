// Copyright 2017 The go-ethereum Authors
// (original work)
// Copyright 2024 The Erigon Authors
// (modifications)
// Copyright 2025 The TracExp Authors
// (modifications)
//
// Erigon is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Erigon is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Erigon. If not, see <http://www.gnu.org/licenses/>.

// this is a modified version of the callTracer, which is a full blown transaction tracer
{
	debug: false, // whether to print debug information, default is false

	ignore_staticall: true, // whether to ignore static calls, default is true

	stack: [], // Stack of inputs and calls, used to track the current context

	nodes: [], // Call stack, node = { type, from, to, createdAddress?, input, value?, ops[], calls[], error?, ... }

	// npops is a map of opcodes to the number of stack items they pop (read).
	npops: {48: 0, 49: 1, 53: 1, 54: 0, 55: 3, 56: 0, 57: 3, 58: 0, 59: 1, 60: 4, 61: 0, 62: 3, 64: 1, 65: 0, 66: 0, 67: 0, 68: 0, 69: 0, 70: 0, 71: 0, 72: 0, 73: 1, 74: 0, 84: 1, 86: 1, 87: 2, 90: 0, 92: 1, 95: 0, 96: 0, 97: 0, 98: 0, 99: 0, 100: 0, 101: 0, 102: 0, 103: 0, 104: 0, 105: 0, 106: 0, 107: 0, 108: 0, 109: 0, 110: 0, 111: 0, 112: 0, 113: 0, 114: 0, 115: 0, 116: 0, 117: 0, 118: 0, 119: 0, 120: 0, 121: 0, 122: 0, 123: 0, 124: 0, 125: 0, 126: 0, 127: 0, 241: 7, 242: 7, 244: 6, 250: 6},
	// npops: {0: 0, 1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 3, 9: 3, 10: 2, 11: 2, 16: 2, 17: 2, 18: 2, 19: 2, 20: 2, 21: 1, 22: 2, 23: 2, 24: 2, 25: 1, 26: 2, 27: 2, 28: 2, 29: 2, 32: 2, 48: 0, 49: 1, 50: 0, 51: 0, 52: 0, 53: 1, 54: 0, 55: 3, 56: 0, 57: 3, 58: 0, 59: 1, 60: 4, 61: 0, 62: 3, 63: 1, 64: 1, 65: 0, 66: 0, 67: 0, 68: 0, 69: 0, 70: 0, 71: 0, 72: 0, 73: 1, 80: 1, 81: 1, 82: 2, 83: 2, 84: 1, 85: 2, 86: 1, 87: 2, 88: 0, 89: 0, 90: 0, 91: 0, 92: 1, 93: 2, 94: 3, 95: 0, 96: 0, 97: 0, 98: 0, 99: 0, 100: 0, 101: 0, 102: 0, 103: 0, 104: 0, 105: 0, 106: 0, 107: 0, 108: 0, 109: 0, 110: 0, 111: 0, 112: 0, 113: 0, 114: 0, 115: 0, 116: 0, 117: 0, 118: 0, 119: 0, 120: 0, 121: 0, 122: 0, 123: 0, 124: 0, 125: 0, 126: 0, 127: 0, 128: 1, 129: 2, 130: 3, 131: 4, 132: 5, 133: 6, 134: 7, 135: 8, 136: 9, 137: 10, 138: 11, 139: 12, 140: 13, 141: 14, 142: 15, 143: 16, 144: 2, 145: 3, 146: 4, 147: 5, 148: 6, 149: 7, 150: 8, 151: 9, 152: 10, 153: 11, 154: 12, 155: 13, 156: 14, 157: 15, 158: 16, 159: 17, 160: 2, 161: 3, 162: 4, 163: 5, 164: 6, 240: 3, 241: 7, 242: 7, 243: 2, 244: 6, 245: 4, 250: 6, 253: 2, 254: 0, 255: 1},

	// npushes is a map of opcodes to the number of stack items they push.
	// This is used to determine how many items to write into the stack.
	npushes: {48: 1, 49: 1, 53: 1, 54: 1, 55: 0, 56: 1, 57: 0, 58: 1, 59: 1, 60: 0, 61: 1, 62: 0, 64: 1, 65: 1, 66: 1, 67: 1, 68: 1, 69: 1, 70: 1, 71: 1, 72: 1, 73: 1, 74: 1, 84: 1, 86: 0, 87: 0, 90: 1, 92: 1, 95: 1, 96: 1, 97: 1, 98: 1, 99: 1, 100: 1, 101: 1, 102: 1, 103: 1, 104: 1, 105: 1, 106: 1, 107: 1, 108: 1, 109: 1, 110: 1, 111: 1, 112: 1, 113: 1, 114: 1, 115: 1, 116: 1, 117: 1, 118: 1, 119: 1, 120: 1, 121: 1, 122: 1, 123: 1, 124: 1, 125: 1, 126: 1, 127: 1, 241: 1, 242: 1, 244: 1, 250: 1},
	// npushes: {0: 0, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 16: 1, 17: 1, 18: 1, 19: 1, 20: 1, 21: 1, 22: 1, 23: 1, 24: 1, 25: 1, 26: 1, 27: 1, 28: 1, 29: 1, 32: 1, 48: 1, 49: 1, 50: 1, 51: 1, 52: 1, 53: 1, 54: 1, 55: 0, 56: 1, 57: 0, 58: 1, 59: 1, 60: 0, 61: 1, 62: 0, 63: 1, 64: 1, 65: 1, 66: 1, 67: 1, 68: 1, 69: 1, 70: 1, 71: 1, 72: 1, 73: 1, 80: 0, 81: 1, 82: 0, 83: 0, 84: 1, 85: 0, 86: 0, 87: 0, 88: 1, 89: 1, 90: 1, 91: 0, 92: 1, 93: 0, 94: 0, 95: 1, 96: 1, 97: 1, 98: 1, 99: 1, 100: 1, 101: 1, 102: 1, 103: 1, 104: 1, 105: 1, 106: 1, 107: 1, 108: 1, 109: 1, 110: 1, 111: 1, 112: 1, 113: 1, 114: 1, 115: 1, 116: 1, 117: 1, 118: 1, 119: 1, 120: 1, 121: 1, 122: 1, 123: 1, 124: 1, 125: 1, 126: 1, 127: 1, 128: 2, 129: 3, 130: 4, 131: 5, 132: 6, 133: 7, 134: 8, 135: 9, 136: 10, 137: 11, 138: 12, 139: 13, 140: 14, 141: 15, 142: 16, 143: 17, 144: 2, 145: 3, 146: 4, 147: 5, 148: 6, 149: 7, 150: 8, 151: 9, 152: 10, 153: 11, 154: 12, 155: 13, 156: 14, 157: 15, 158: 16, 159: 17, 160: 0, 161: 0, 162: 0, 163: 0, 164: 0, 240: 1, 241: 1, 242: 1, 243: 0, 244: 1, 245: 1, 250: 1, 253: 0, 254: 0, 255: 0},
	
	// fault is invoked when the actual execution of an opcode fails.
	fault: function(log, db) {	},

	// step is invoked for every opcode that the VM executes.
	step: function(log, db) {
		// We only care about system opcodes, faster if we pre-check once
		const pc = log.getPC();
		const op = log.op.toNumber();
		const opName = log.op.toString();
		const depth = log.getDepth();
		
		const isCreate = opName === 'CREATE' || opName === 'CREATE2';
		const isCall = opName === 'CALL' || opName === 'CALLCODE' || opName === 'DELEGATECALL' || opName === 'STATICCALL';
		const isTerminal = opName === 'RETURN' || opName === 'STOP' || opName === 'SELFDESTRUCT';
		const isRevert = opName === 'REVERT';
		const isLog = opName === 'LOG0' || opName === 'LOG1' || opName === 'LOG2' || opName === 'LOG3' || opName === 'LOG4';
		const toRecord = opName === 'CODECOPY' || opName === 'EXTCODECOPY' || opName === 'RETURNDATACOPY' || opName === 'CALLDATACOPY' || opName === 'LOG0' || opName === 'LOG1' || opName === 'LOG2' || opName === 'LOG3' || opName === 'LOG4';

		if (this.nodes.length == 0) {
			// Create a new call node
			this.stack.push({
				call: "",
				input: "",
				contract: "",
			})
			currentNode = {
				depth: depth,
				contract: "",
				call: "",
				input: "",
				ops: [],
			};

			if (this.debug) {
				currentNode.stack = this.stack.concat(); // for debug
			}

			this.nodes.push(currentNode);

		} else {
			currentNode = this.nodes[this.nodes.length - 1];
		}

		var error = log.getError();
		if (error !== undefined) {
			this.stack.pop();
			return;
		}

		// context switches to a new contract or depth
		if (depth != currentNode.depth) {
			top = this.stack[this.stack.length-1];
			if (top.contract.length == 0 && (top.call == "CREATE" || top.call == "CREATE2")) {
				top.contract = toHex(log.contract.getAddress()); // Set the contract for the top of the stack
			}

			newNode = {
				depth: depth,
				contract: top.contract,
				call: top.call,
				input: top.input,
				ops: [],
			}

			if (this.debug) {
				newNode.stack = this.stack.concat(); // for debug
			}

			this.nodes.push(newNode);
			currentNode = newNode;
		} else if (currentNode.ops.length > 0 && currentNode.ops.length - 1 >= 0 && this.is_call(currentNode.ops[currentNode.ops.length - 1].opName)) {
			this.stack.pop(); // Pop the last call from the stack if we are still in the same depth and the last operation was a CALL or CALLCODE (only ether transfer)
		}

		if (this.ignore_staticall && currentNode.call == "STATICCALL" && !isTerminal && !isRevert && !isCreate && !isCall) {
			// If we are in a static call, we don't want to record any operations
			return;
		}

		var opinfo = { pc, op, opName };

		// Collect stack items that are read by this opcode
		// Add this opinfo to the current call's operations
		var nPop = 0;
		if(op in this.npops) {
			nPop = this.npops[op];
		}
		var stackLen = log.stack.length();
		
		if (nPop > 0) {
			opinfo.pops = [];
			for (var i = 0; i < nPop && i < stackLen; i++) {
				opinfo.pops.push(log.stack.peek(i).toString(16));
				// opinfo.pops.push(toHex(toWord(log.stack.peek(i).toString(16))));
				// opinfo.pops.push(log.stack.peek(i).valueOf());
			}	
		}
		if (currentNode.ops.length > 0) {
			var prevopidx = currentNode.ops.length - 1;
			if (prevopidx >= 0) {
				var prevop = currentNode.ops[prevopidx];

				var npush = 0;
				if (prevop.op in this.npushes) {
					npush = this.npushes[prevop.op];
				}
				
				if (npush > 0) {
					prevop.pushes = [];
					for (var i = 0; i < npush && i < stackLen; i++) {
						// prevop.pushes.push(toHex(toWord(log.stack.peek(i).toString(16))));
						// prevop.pushes.push(log.stack.peek(i).valueOf());
						prevop.pushes.push(log.stack.peek(i).toString(16));
					}
				}

				if (prevop.dstOffset === undefined || prevop.dstLength === undefined) {
				} else {
					// If the previous operation does not have a destination offset, we can set it to the current opcode's offset
					prevop.output = toHex(log.memory.slice(prevop.dstOffset, prevop.dstOffset + prevop.dstLength));
					
					delete prevop.dstOffset; // Remove dstOffset from the previous operation
					delete prevop.dstLength; // Remove dstLength from the previous operation
				}
			}
		}

		if (isLog) {
			var inOff = log.stack.peek(0).valueOf();
			var inEnd = inOff + log.stack.peek(1).valueOf();
			
			opinfo.value = toHex(log.memory.slice(inOff, inEnd));
		}

		if (isCreate) {
			// If a new contract is being created, add to the call stack
			var inOff = log.stack.peek(1).valueOf();
			var inEnd = inOff + log.stack.peek(2).valueOf();
			
			opinfo.from = toHex(log.contract.getAddress());
			opinfo.input = toHex(log.memory.slice(inOff, inEnd));
			opinfo.value = '0x' + log.stack.peek(0).toString(16);

			this.stack.push({
				call: opinfo.opName,
				input: opinfo.input,
				contract: "",
			});

		} else if (isCall) {
			// Skip any pre-compile invocations, those are just fancy opcodes
			var to = toAddress(log.stack.peek(1).toString(16));
			if (!isPrecompiled(to)) {
				var off = (opName == 'DELEGATECALL' || opName == 'STATICCALL' ? 0 : 1);

				var inOff = log.stack.peek(2 + off).valueOf();
				var inEnd = inOff + log.stack.peek(3 + off).valueOf();

				opinfo.from = toHex(log.contract.getAddress());
				opinfo.to = toHex(to);
				opinfo.input = toHex(log.memory.slice(inOff, inEnd));
				if (opName != 'DELEGATECALL' && opName != 'STATICCALL') {
					opinfo.value = '0x' + log.stack.peek(2).toString(16);
				}
			}
			// even if the call is to a pre-compile, we still want to record the call as it will popped later
			this.stack.push({
				call: opinfo.opName,
				input: opinfo.input,
				contract: opinfo.to,
			});

		} else if (isTerminal || isRevert) {
			top = this.stack.pop(); // Pop the current context from the stack
			if (opName == 'RETURN') {
				var offset = log.stack.peek(0);
				var length = log.stack.peek(1);
				opinfo.output = toHex(log.memory.slice(offset, offset + length)); // the outLen may be 0 for dynamic-length data
			}
		}

		if (toRecord) {
			if (opName == 'EXTCODECOPY') {
				opinfo.dstOffset = log.stack.peek(1).valueOf();
				opinfo.dstLength = log.stack.peek(3).valueOf();
			} else if (opName == 'CODECOPY' || opName == 'RETURNDATACOPY' || opName == 'CALLDATACOPY') {
				opinfo.dstOffset = log.stack.peek(0).valueOf();
				opinfo.dstLength = log.stack.peek(2).valueOf();
			} else {
				opinfo.dstOffset = log.stack.peek(0).valueOf();
				opinfo.dstLength = log.stack.peek(1).valueOf();
			}
		}

		currentNode.ops.push(opinfo);
	},

	is_call: function(op) {
		// Check if the opcode is a call opcode
		return op === 'CALL' || op === 'CALLCODE' || op === 'DELEGATECALL' || op === 'STATICCALL';
	},

	// result is invoked when all the opcodes have been iterated over and returns
	// the final result of the tracing.
	result: function(ctx, db) {
		var input = toHex(ctx.input);
		for (var i = 0; i < this.nodes.length; i++) {
			var node = this.nodes[i];
			if (node.input.length == 0 && node.depth == 1) {
				node.input = input; // Set the input for the outermost call
				node.call = ctx.type; // Set the call type for the outermost call
				node.contract = toHex(ctx.to); // Set the contract for the outermost call
				node.sender = toHex(ctx.from); // Set the sender for the outermost call
				node.value = ctx.value; // Set the value for the outermost call
			}
		}
		return {efg: this.nodes};
	},
}