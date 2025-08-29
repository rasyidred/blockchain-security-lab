// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title SecureBank - A reentrancy-protected bank contract
/// @notice This contract demonstrates proper protection against reentrancy attacks
/// @dev Uses OpenZeppelin's ReentrancyGuard and follows CEI pattern
contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /// @notice Deposit ether to the bank
    function deposit() external payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Withdraw all balance (PROTECTED FROM REENTRANCY)
    /// @dev Uses ReentrancyGuard modifier and follows CEI pattern
    function withdraw() external nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // SECURITY: State update BEFORE external call (CEI pattern)
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, balance);

        // External call happens AFTER state update
        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    /// @notice Alternative secure withdraw using address.transfer()
    /// @dev transfer() provides gas limit protection but is less flexible
    function withdrawWithTransfer() external nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // State update before external call
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, balance);

        // transfer() limits gas to 2300, preventing reentrancy
        payable(msg.sender).transfer(balance);
    }

    /// @notice Get balance of an address
    /// @param user The address to check balance for
    /// @return The balance of the user
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    /// @notice Get contract's total ether balance
    /// @return The total ether held by the contract
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
