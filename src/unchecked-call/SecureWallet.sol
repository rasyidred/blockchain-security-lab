// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/// @title SecureWallet - A wallet contract with proper external call handling
/// @notice This contract demonstrates secure handling of external calls
/// @dev Uses proper error handling and validation for all external interactions
contract SecureWallet is ReentrancyGuard {
    using Address for address;
    using Address for address payable;

    mapping(address => uint256) public balances;
    mapping(address => bool) public isOwner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnerAdded(address indexed newOwner);
    event ExternalCallMade(address indexed target, bytes data, bool success);
    event CallFailed(address indexed target, bytes data, bytes reason);

    error CallFailedError(address target, bytes data);
    error InsufficientBalance(uint256 requested, uint256 available);
    error InvalidAddress();
    error NotAnOwner();
    error ZeroAmount();

    modifier onlyOwner() {
        if (!isOwner[msg.sender]) revert NotAnOwner();
        _;
    }

    constructor() {
        isOwner[msg.sender] = true;
    }

    /// @notice Deposit ether to the wallet
    function deposit() external payable {
        if (msg.value == 0) revert ZeroAmount();
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Withdraw funds (SECURE - checked call)
    /// @param amount Amount to withdraw
    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (balances[msg.sender] < amount) {
            revert InsufficientBalance(amount, balances[msg.sender]);
        }

        balances[msg.sender] -= amount;

        // SECURITY: Check call success and revert on failure
        (bool success,) = payable(msg.sender).call{value: amount}("");
        if (!success) {
            balances[msg.sender] += amount; // Restore balance on failure
            revert CallFailedError(msg.sender, bytes(""));
        }

        emit Withdrawal(msg.sender, amount);
    }

    /// @notice Alternative secure withdraw using Address.sendValue
    /// @param amount Amount to withdraw
    function withdrawSafe(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        if (balances[msg.sender] < amount) {
            revert InsufficientBalance(amount, balances[msg.sender]);
        }

        balances[msg.sender] -= amount;

        // SECURITY: Using OpenZeppelin's Address.sendValue for safe transfer
        payable(msg.sender).sendValue(amount);

        emit Withdrawal(msg.sender, amount);
    }

    /// @notice Batch withdraw to multiple addresses (SECURE)
    /// @param recipients Array of recipient addresses
    /// @param amounts Array of amounts to send
    function batchWithdraw(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner nonReentrant {
        if (recipients.length != amounts.length) {
            revert("Arrays length mismatch");
        }

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            if (recipients[i] == address(0)) revert InvalidAddress();
            if (amounts[i] == 0) revert ZeroAmount();
            totalAmount += amounts[i];
        }

        if (address(this).balance < totalAmount) {
            revert InsufficientBalance(totalAmount, address(this).balance);
        }

        for (uint256 i = 0; i < recipients.length; i++) {
            // SECURITY: Check each call and handle failures
            (bool success,) = payable(recipients[i]).call{value: amounts[i]}("");
            if (!success) {
                emit CallFailed(recipients[i], "", "Transfer failed");
                // Option 1: Revert entire batch on any failure
                revert CallFailedError(recipients[i], bytes(""));
                // Option 2: Continue with other transfers (commented out)
                // continue;
            }
            emit Withdrawal(recipients[i], amounts[i]);
        }
    }

    /// @notice Execute arbitrary external call (SECURE with proper validation)
    /// @param target Target contract address
    /// @param data Call data
    /// @return success Whether call succeeded
    /// @return returnData Data returned from call
    function executeCall(address target, bytes calldata data)
        external
        onlyOwner
        nonReentrant
        returns (bool success, bytes memory returnData)
    {
        if (target == address(0)) revert InvalidAddress();

        // SECURITY: Prevent calls to this contract to avoid privilege escalation
        require(target != address(this), "Cannot call self");

        // SECURITY: Proper call handling with return value checking
        (success, returnData) = target.call(data);

        emit ExternalCallMade(target, data, success);

        if (!success) {
            // Extract revert reason if available
            if (returnData.length > 0) {
                assembly {
                    let returndata_size := mload(returnData)
                    revert(add(32, returnData), returndata_size)
                }
            }
            revert CallFailedError(target, data);
        }

        return (success, returnData);
    }

    /// @notice Send ether to address (SECURE - checked call)
    /// @param recipient Recipient address
    /// @param amount Amount to send
    function sendEther(address recipient, uint256 amount) external onlyOwner nonReentrant {
        if (recipient == address(0)) revert InvalidAddress();
        if (amount == 0) revert ZeroAmount();
        if (address(this).balance < amount) {
            revert InsufficientBalance(amount, address(this).balance);
        }

        // SECURITY: Using OpenZeppelin's sendValue for secure transfer
        payable(recipient).sendValue(amount);

        emit Withdrawal(recipient, amount);
    }

    /// @notice Emergency withdrawal (SECURE with proper error handling)
    /// @dev Sends all funds to caller, reverts if transfer fails
    function emergencyWithdraw() external onlyOwner nonReentrant {
        uint256 contractBalance = address(this).balance;
        if (contractBalance == 0) return;

        // SECURITY: Check call success, revert on failure
        (bool success,) = payable(msg.sender).call{value: contractBalance}("");
        if (!success) {
            revert CallFailedError(msg.sender, bytes("Emergency withdrawal failed"));
        }

        emit Withdrawal(msg.sender, contractBalance);
    }

    /// @notice Forward call to another contract (SECURE with validation)
    /// @param target Target contract
    /// @param data Call data
    /// @return success Whether call succeeded
    /// @return result Call result data
    function forwardCall(address target, bytes calldata data)
        external
        onlyOwner
        nonReentrant
        returns (bool success, bytes memory result)
    {
        if (target == address(0)) revert InvalidAddress();
        require(target != address(this), "Cannot call self");

        // SECURITY: Always check call success
        (success, result) = target.call(data);

        if (!success) {
            emit CallFailed(target, data, result);
            revert CallFailedError(target, data);
        }

        emit ExternalCallMade(target, data, success);
        return (success, result);
    }

    /// @notice Multi-call function (SECURE with individual error handling)
    /// @param targets Array of target addresses
    /// @param callDatas Array of call data
    /// @param continueOnFailure Whether to continue if individual calls fail
    /// @return results Array of results
    /// @return successes Array of success flags
    function multiCall(address[] calldata targets, bytes[] calldata callDatas, bool continueOnFailure)
        external
        onlyOwner
        nonReentrant
        returns (bytes[] memory results, bool[] memory successes)
    {
        if (targets.length != callDatas.length) {
            revert("Arrays length mismatch");
        }

        results = new bytes[](targets.length);
        successes = new bool[](targets.length);

        for (uint256 i = 0; i < targets.length; i++) {
            if (targets[i] == address(0)) revert InvalidAddress();
            require(targets[i] != address(this), "Cannot call self");

            // SECURITY: Proper handling of individual call results
            (successes[i], results[i]) = targets[i].call(callDatas[i]);

            emit ExternalCallMade(targets[i], callDatas[i], successes[i]);

            if (!successes[i]) {
                emit CallFailed(targets[i], callDatas[i], results[i]);

                if (!continueOnFailure) {
                    revert CallFailedError(targets[i], callDatas[i]);
                }
            }
        }

        return (results, successes);
    }

    /// @notice Add new owner (SECURE with proper call handling)
    /// @param newOwner Address of new owner
    /// @param notificationContract Contract to notify of new owner
    function addOwnerWithNotification(address newOwner, address notificationContract) external onlyOwner nonReentrant {
        if (newOwner == address(0)) revert InvalidAddress();
        require(!isOwner[newOwner], "Already an owner");

        isOwner[newOwner] = true;
        emit OwnerAdded(newOwner);

        // SECURITY: Handle notification call properly
        if (notificationContract != address(0)) {
            bytes memory callData = abi.encodeWithSignature("onOwnerAdded(address)", newOwner);
            (bool success, bytes memory returnData) = notificationContract.call(callData);

            if (!success) {
                emit CallFailed(notificationContract, callData, returnData);
                // Revert owner addition if notification is critical
                isOwner[newOwner] = false;
                revert CallFailedError(notificationContract, callData);
            }

            emit ExternalCallMade(notificationContract, callData, success);
        }
    }

    /// @notice Add owner without critical notification (continues if notification fails)
    /// @param newOwner Address of new owner
    /// @param notificationContract Contract to notify of new owner
    function addOwnerWithOptionalNotification(address newOwner, address notificationContract) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAddress();
        require(!isOwner[newOwner], "Already an owner");

        isOwner[newOwner] = true;
        emit OwnerAdded(newOwner);

        // SECURITY: Optional notification - owner is added even if this fails
        if (notificationContract != address(0)) {
            bytes memory callData = abi.encodeWithSignature("onOwnerAdded(address)", newOwner);
            (bool success, bytes memory returnData) = notificationContract.call(callData);

            emit ExternalCallMade(notificationContract, callData, success);

            if (!success) {
                emit CallFailed(notificationContract, callData, returnData);
                // Don't revert - notification failure is non-critical
            }
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
