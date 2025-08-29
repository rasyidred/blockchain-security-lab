// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title VulnerableBank - A contract vulnerable to reentrancy attacks
/// @notice This contract demonstrates a classic reentrancy vulnerability
/// @dev WARNING: This contract is intentionally vulnerable for educational purposes
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /// @notice Deposit ether to the bank
    function deposit() external payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Withdraw all balance (VULNERABLE TO REENTRANCY)
    /// @dev This function violates the Checks-Effects-Interactions pattern
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success,) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call - this is the vulnerability
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, balance);
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
