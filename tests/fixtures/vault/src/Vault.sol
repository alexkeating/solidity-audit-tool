// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Math} from "dep/Math.sol";
import {Ownable} from "./Ownable.sol";

contract Vault is Ownable {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
        totalDeposits = Math.sub(totalDeposits, amount);
    }

    function setFee(uint256 fee) public {
        feeBps = fee;
    }

    function sweep(address to) external onlyOwner {
        payable(to).transfer(address(this).balance);
    }
}
