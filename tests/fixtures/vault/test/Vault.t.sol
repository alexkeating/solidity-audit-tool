// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "src/Vault.sol";

contract VaultTest {
    function test_DepositRecordsBalance() public {
        Vault vault = new Vault();
        vault.deposit{value: 0}();
        require(vault.balances(address(this)) == 0, "balance");
    }
}
