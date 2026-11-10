// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Token {
    mapping(address => uint256) public balanceOf;

    function mint(uint256 amount) external {
        balanceOf[msg.sender] += amount;
    }
}
