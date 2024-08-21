// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ERC20} from "@openzeppelin/ERC20.sol";
import {Ownable} from "@openzeppelin/Ownable.sol";

/// @title HEU
/// @notice HEU token contract.
contract HEU is ERC20, Ownable {
    /// CONSTANTS ///

    uint256 public constant MAXIMUM_SUPPLY = 1_000_000_000e18;

    /// ERRORS ///

    error HEU__CanNotExceedMaximumSupply();

    constructor() ERC20("Heurist", "HEU") Ownable(msg.sender) {}

    function mint(address recipient, uint256 amount) external onlyOwner {
        if (totalSupply() + amount > MAXIMUM_SUPPLY) {
            revert HEU__CanNotExceedMaximumSupply();
        }

        _mint(recipient, amount);
    }
}
