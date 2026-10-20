// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../interface.sol";

// Contracts involved
// PLACEHOLDERS
// e.g., address constant pancakeV3Pool = 0x36696169C63e42cd08ce11f5deeBbCeBae652050;

contract ContractTest is Test {
    address attacker = makeAddr("attacker");

    function setUp() public {
        vm.createSelectFork({chain}, {blocknumber});
        vm.deal(attacker, 1 ether); // assumption the balance
    }

    function testPoC() public {
        vm.startPrank(attacker);
        // before attack
        // instrumentation
        AttackerC attC = new AttackerC();
        attC.attack();
        // after attack
        // instrumentation
        // console2.log("Profit:", IERC20(BUSD).balanceOf(attacker) / 1e18, 'BUSD');
        vm.stopPrank();
    }
}

contract AttackerC {
    function attack() external payable {
        <PLACEHOLDER>
    }

    <PLACEHODER>
}

// Interface for interacting with the vulnerable contract
// Or other contracts