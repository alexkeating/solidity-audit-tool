// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract Ownable {
    address public owner = msg.sender;
    uint256 public feeBps;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
}
