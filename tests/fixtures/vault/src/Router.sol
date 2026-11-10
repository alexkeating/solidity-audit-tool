// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Vault} from "./Vault.sol";

contract Router {
    function depositFor(Vault vault) external payable {
        vault.deposit{value: msg.value}();
    }
}
