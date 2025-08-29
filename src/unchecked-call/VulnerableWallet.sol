// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title VulnerableWallet - A wallet contract vulnerable to unchecked external calls
/// @notice This contract demonstrates vulnerabilities from unchecked call return values
/// @dev WARNING: This contract is intentionally vulnerable for educational purposes
contract VulnerableWallet {
    mapping(address => uint256) public balances;
    mapping(address => bool) public isOwner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnerAdded(address indexed newOwner);
    event ExternalCallMade(address indexed target, bytes data, bool success);

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Not an owner");
        _;
    }

    constructor() {
        isOwner[msg.sender] = true;
    }

    /// @notice Deposit ether to the wallet
    function deposit() external payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Withdraw funds (VULNERABLE - unchecked call)
    /// @param amount Amount to withdraw
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be greater than 0");

        balances[msg.sender] -= amount;

        // VULNERABILITY: Call return value not checked
        msg.sender.call{value: amount}("");

        emit Withdrawal(msg.sender, amount);
    }

    /// @notice Batch withdraw to multiple addresses (VULNERABLE)
    /// @param recipients Array of recipient addresses
    /// @param amounts Array of amounts to send
    function batchWithdraw(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner {
        require(recipients.length == amounts.length, "Arrays length mismatch");

        for (uint256 i = 0; i < recipients.length; i++) {
            require(amounts[i] > 0, "Amount must be greater than 0");
            require(address(this).balance >= amounts[i], "Insufficient contract balance");

            // VULNERABILITY: External call return value ignored
            payable(recipients[i]).call{value: amounts[i]}("");

            emit Withdrawal(recipients[i], amounts[i]);
        }
    }

    /// @notice Execute arbitrary external call (HIGHLY VULNERABLE)
    /// @param target Target contract address
    /// @param data Call data
    function executeCall(address target, bytes calldata data) external onlyOwner {
        require(target != address(0), "Invalid target address");

        // VULNERABILITY: No validation on call success, could be exploited
        (bool success,) = target.call(data);

        emit ExternalCallMade(target, data, success);
    }

    /// @notice Send ether to address (VULNERABLE - unchecked)
    /// @param recipient Recipient address
    /// @param amount Amount to send
    function sendEther(address recipient, uint256 amount) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        require(amount > 0, "Amount must be greater than 0");
        require(address(this).balance >= amount, "Insufficient balance");

        // VULNERABILITY: Call could fail but function continues
        payable(recipient).call{value: amount}("");

        emit Withdrawal(recipient, amount);
    }

    /// @notice Emergency withdrawal (VULNERABLE)
    /// @dev Attempts to send all funds to owner, ignores failures
    function emergencyWithdraw() external onlyOwner {
        uint256 contractBalance = address(this).balance;

        if (contractBalance > 0) {
            // VULNERABILITY: If this call fails, funds remain stuck
            payable(msg.sender).call{value: contractBalance}("");

            emit Withdrawal(msg.sender, contractBalance);
        }
    }

    /// @notice Forward call to another contract (VULNERABLE)
    /// @param target Target contract
    /// @param data Call data
    /// @return result Call result data
    function forwardCall(address target, bytes calldata data) external onlyOwner returns (bytes memory result) {
        require(target != address(0), "Invalid target");

        // VULNERABILITY: Doesn't check if call succeeded
        (, result) = target.call(data);

        // Returns whatever was returned, even if call failed
        return result;
    }

    /// @notice Multi-call function (VULNERABLE)
    /// @param targets Array of target addresses
    /// @param callDatas Array of call data
    /// @return results Array of results
    function multiCall(address[] calldata targets, bytes[] calldata callDatas)
        external
        onlyOwner
        returns (bytes[] memory results)
    {
        require(targets.length == callDatas.length, "Arrays length mismatch");

        results = new bytes[](targets.length);

        for (uint256 i = 0; i < targets.length; i++) {
            // VULNERABILITY: Individual call failures are not handled
            (, results[i]) = targets[i].call(callDatas[i]);
        }

        return results;
    }

    /// @notice Add new owner (VULNERABLE - external call)
    /// @param newOwner Address of new owner
    /// @param notificationContract Contract to notify of new owner
    function addOwnerWithNotification(address newOwner, address notificationContract) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        require(!isOwner[newOwner], "Already an owner");

        isOwner[newOwner] = true;
        emit OwnerAdded(newOwner);

        // VULNERABILITY: External call could fail but owner is still added
        if (notificationContract != address(0)) {
            notificationContract.call(abi.encodeWithSignature("onOwnerAdded(address)", newOwner));
        }
    }

    /// @notice Get contract balance
    /// @return Current contract balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Get user balance
    /// @param user User address
    /// @return User's balance
    function getUserBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    /// @notice Check if address is owner
    /// @param user Address to check
    /// @return Whether address is owner
    function checkOwner(address user) external view returns (bool) {
        return isOwner[user];
    }

    /// @notice Receive function to accept ether
    receive() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
}
