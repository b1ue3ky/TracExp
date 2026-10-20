// Copyright 2017 The go-Nativeereum Authors
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
	tokenflows: [], // Stack of inputs and calls, used to track the current context

    logs: [],

	// fault is invoked when the actual execution of an opcode fails.
	fault: function(log, db) {	},

	// step is invoked for every opcode that the VM executes.
	step: function(log, db) {
		// We only care about system opcodes, faster if we pre-check once
		const opName = log.op.toString();
		
        if (this.tokenflows.length > 0 && this.tokenflows[this.tokenflows.length - 1].to.length == 0) {
            this.tokenflows[this.tokenflows.length - 1].to = toHex(log.contract.getAddress()); // new created contracts
        }
        
		if (opName === "LOG3") {
			var inOff = log.stack.peek(0).valueOf();
			var inEnd = inOff + log.stack.peek(1).valueOf();

            var topic0 = '0x' + log.stack.peek(2).toString(16);
            var topic1 = '0x' + log.stack.peek(3).toString(16);
            var topic2 = '0x' + log.stack.peek(4).toString(16);
            var value = toHex(log.memory.slice(inOff, inEnd));
                        
            // this.logs.push({"token": toHex(log.contract.getAddress()), "topic0": topic0, "topic1": topic1, "topic2": topic2, "value": value});

            // Transfer Event
            if (topic0 === "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef") {
                if (value && value.length > 2 && value != '0x0') {
                    this.tokenflows.push({
                        "event": "Transfer",
                        "token": toHex(log.contract.getAddress()),
                        "from": topic1,
                        "to": topic2,
                        "value": value
                    })
                }
            } else if (topic0 === "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925") {
                // Approval Event
                if (value && value.length > 2 && value != '0x0') {
                    this.tokenflows.push({
                        "event": "Approval",
                        "token": toHex(log.contract.getAddress()),
                        "from": topic1,
                        "to": topic2,
                        "value": value
                    })
                }
            }
		}

        if (opName === "LOG2") {
            var inOff = log.stack.peek(0).valueOf();
			var inEnd = inOff + log.stack.peek(1).valueOf();

            var topic0 = '0x' + log.stack.peek(2).toString(16);
            var topic1 = '0x' + log.stack.peek(3).toString(16);
            var value = toHex(log.memory.slice(inOff, inEnd));

            if (topic0 == "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c") {
                // Deposit Event
                if (value && value.length > 2 && value != '0x0') {
                    this.tokenflows.push({
                        "event": "Deposit",
                        "token": toHex(log.contract.getAddress()),
                        "from": toHex(log.contract.getAddress()),
                        "to": topic1,
                        "value": value
                    })
                }
            } else if (topic0 == "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65") {
                // Withdrawal Event
                if (value && value.length > 2 && value != '0x0') {
                    this.tokenflows.push({
                        "event": "Withdrawal",
                        "token": toHex(log.contract.getAddress()),
                        "from": topic1,
                        "to": toHex(log.contract.getAddress()),
                        "value": value
                    })
                }
            }
        }

		if (opName === 'CREATE' || opName === 'CREATE2') {
			var value = '0x' + log.stack.peek(0).toString(16);
            
            if (value.length > 2 && value != '0x0') {
                this.tokenflows.push({
                    "event": "Transfer",
                    "token": "Native",
                    "from": toHex(log.contract.getAddress()),
                    "to": "",
                    "value": value
                });
            }
		} else if (opName === 'CALL' || opName === 'CALLCODE') {
			// Skip any pre-compile invocations, those are just fancy opcodes
			var to = toAddress(log.stack.peek(1).toString(16));
			if (!isPrecompiled(to)) {
                var value = '0x' + log.stack.peek(2).toString(16);
                if (value.length > 2 && value != '0x0') {
                    this.tokenflows.push({
                        "event": "Transfer",
                        "token": "Native",
                        "from": toHex(log.contract.getAddress()),
                        "to": toHex(to),
                        "value": value
                    });
                }
			}
		} else if (opName === 'SELFDESTRUCT') {
            var to = toAddress(log.stack.peek(0).toString(16));
            var value = '0x' + db.getBalance(log.contract.getAddress()).toString(16);
            if (value.length  > 2 && value != '0x0') {
                this.tokenflows.push({
                    "event": "Transfer",
                    "token": "Native",
                    "from": toHex(log.contract.getAddress()),
                    "to": toHex(to),
                    "value": value
                });
            }
		}
	},

    // result is invoked when all the opcodes have been iterated over and returns
	// the final result of the tracing.
	result: function(ctx, db) {
        var value = '0x' + ctx.value.toString(16);
        if (value.length > 2 && value != '0x0') {
            this.tokenflows.unshift({
                "event": "Transfer",
                "token": "Native",
                "from": toHex(ctx.from),
                "to": toHex(ctx.to),
                "value": value
            });
        }

		return {tokenflows: this.tokenflows};
	},
}