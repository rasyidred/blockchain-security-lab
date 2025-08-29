// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title SecureDistributor - A DOS-resistant reward distribution contract
/// @notice This contract demonstrates secure techniques to prevent DOS attacks
/// @dev Uses pull pattern, pagination, and gas-efficient data structures
contract SecureDistributor is ReentrancyGuard, Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;

    // Use EnumerableSet for efficient participant management
    EnumerableSet.AddressSet private participants;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public totalClaimed;

    uint256 public totalRewards;
    uint256 public totalDistributed;
    uint256 public constant MAX_BATCH_SIZE = 50; // Prevent DOS via large batches
    uint256 public constant MAX_PARTICIPANTS_PER_TX = 20; // Limit iterations per transaction

    // Pagination state for distribution
    uint256 public currentDistributionIndex;
    uint256 public pendingDistributionAmount;
    bool public distributionInProgress;

    event RewardDeposited(address indexed depositor, uint256 amount);
    event ParticipantAdded(address indexed participant);
    event ParticipantRemoved(address indexed participant);
    event BatchDistributionStarted(uint256 totalAmount, uint256 participantCount);
    event BatchDistributionProgress(uint256 processed, uint256 remaining);
    event BatchDistributionCompleted(uint256 totalDistributed);
    event RewardClaimed(address indexed participant, uint256 amount);
    event DistributionCanceled();

    error TooManyParticipants(uint256 requested, uint256 max);
    error DistributionInProgress();
    error NoDistributionInProgress();
    error ParticipantNotFound();
    error ParticipantExists();
    error InvalidAddress();
    error NoRewardsAvailable();
    error InsufficientRewards();

    modifier noDistributionInProgress() {
        if (distributionInProgress) revert DistributionInProgress();
        _;
    }

    modifier distributionInProgressOnly() {
        if (!distributionInProgress) revert NoDistributionInProgress();
        _;
    }

    constructor() Ownable(msg.sender) {}

    /// @notice Add single participant (GAS-EFFICIENT)
    /// @param participant Address to add as participant
    function addParticipant(address participant) external onlyOwner noDistributionInProgress {
        if (participant == address(0)) revert InvalidAddress();
        if (!participants.add(participant)) revert ParticipantExists();

        emit ParticipantAdded(participant);
    }

    /// @notice Batch add participants with size limit (DOS PROTECTION)
    /// @param newParticipants Array of addresses to add
    function batchAddParticipants(address[] calldata newParticipants) external onlyOwner noDistributionInProgress {
        if (newParticipants.length > MAX_BATCH_SIZE) {
            revert TooManyParticipants(newParticipants.length, MAX_BATCH_SIZE);
        }

        for (uint256 i = 0; i < newParticipants.length; i++) {
            if (newParticipants[i] == address(0)) revert InvalidAddress();
            if (!participants.add(newParticipants[i])) revert ParticipantExists();

            emit ParticipantAdded(newParticipants[i]);
        }
    }

    /// @notice Remove participant (EFFICIENT O(1) removal)
    /// @param participant Address to remove
    function removeParticipant(address participant) external onlyOwner noDistributionInProgress {
        if (!participants.remove(participant)) revert ParticipantNotFound();

        emit ParticipantRemoved(participant);
        // Note: Don't reset balance - allow withdrawal of existing rewards
    }

    /// @notice Deposit rewards for distribution
    function depositRewards() external payable nonReentrant {
        if (msg.value == 0) revert NoRewardsAvailable();
        totalRewards += msg.value;
        emit RewardDeposited(msg.sender, msg.value);
    }

    /// @notice Start batch distribution (SECURE PAGINATION)
    /// @dev Initiates distribution process that can be completed in multiple transactions
    function startDistribution() external onlyOwner noDistributionInProgress nonReentrant {
        if (totalRewards == 0) revert NoRewardsAvailable();

        uint256 participantCount = participants.length();
        if (participantCount == 0) revert NoRewardsAvailable();

        pendingDistributionAmount = totalRewards / participantCount;
        currentDistributionIndex = 0;
        distributionInProgress = true;
        totalRewards = 0; // Clear available rewards

        emit BatchDistributionStarted(pendingDistributionAmount * participantCount, participantCount);
    }

    /// @notice Continue batch distribution (PAGINATED FOR GAS EFFICIENCY)
    /// @dev Processes up to MAX_PARTICIPANTS_PER_TX participants per call
    /// @return completed Whether distribution is fully completed
    function continueDistribution()
        external
        onlyOwner
        distributionInProgressOnly
        nonReentrant
        returns (bool completed)
    {
        uint256 participantCount = participants.length();
        uint256 endIndex = currentDistributionIndex + MAX_PARTICIPANTS_PER_TX;

        if (endIndex > participantCount) {
            endIndex = participantCount;
        }

        // Process batch of participants
        for (uint256 i = currentDistributionIndex; i < endIndex; i++) {
            address participant = participants.at(i);
            balances[participant] += pendingDistributionAmount;
        }

        currentDistributionIndex = endIndex;
        uint256 remaining = participantCount - currentDistributionIndex;

        emit BatchDistributionProgress(endIndex, remaining);

        if (currentDistributionIndex >= participantCount) {
            // Distribution complete
            distributionInProgress = false;
            totalDistributed += pendingDistributionAmount * participantCount;

            emit BatchDistributionCompleted(pendingDistributionAmount * participantCount);
            pendingDistributionAmount = 0;
            currentDistributionIndex = 0;
            return true;
        }

        return false;
    }

    /// @notice Cancel ongoing distribution and refund
    /// @dev Allows canceling if distribution is stuck
    function cancelDistribution() external onlyOwner distributionInProgressOnly {
        uint256 refundAmount = pendingDistributionAmount * participants.length();

        distributionInProgress = false;
        pendingDistributionAmount = 0;
        currentDistributionIndex = 0;
        totalRewards += refundAmount; // Refund undistributed rewards

        emit DistributionCanceled();
    }

    /// @notice Claim individual reward (SECURE PULL PATTERN)
    /// @dev Users pull their own rewards, preventing DOS
    function claimReward() external nonReentrant {
        uint256 amount = balances[msg.sender];
        if (amount == 0) revert NoRewardsAvailable();

        balances[msg.sender] = 0;
        totalClaimed[msg.sender] += amount;

        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit RewardClaimed(msg.sender, amount);
    }

    /// @notice Batch claim for multiple users (with limits)
    /// @param users Array of users to claim for
    /// @dev Only processes up to MAX_BATCH_SIZE users per transaction
    function batchClaim(address[] calldata users) external onlyOwner nonReentrant {
        if (users.length > MAX_BATCH_SIZE) {
            revert TooManyParticipants(users.length, MAX_BATCH_SIZE);
        }

        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 amount = balances[user];

            if (amount > 0) {
                balances[user] = 0;
                totalClaimed[user] += amount;

                (bool success,) = payable(user).call{gas: 10000, value: amount}("");
                if (success) {
                    emit RewardClaimed(user, amount);
                } else {
                    // Restore balance if transfer fails
                    balances[user] = amount;
                    totalClaimed[user] -= amount;
                }
            }
        }
    }

    /// @notice Get paginated list of participants
    /// @param offset Starting index
    /// @param limit Maximum number to return
    /// @return addresses Array of participant addresses
    /// @return total Total number of participants
    function getParticipants(uint256 offset, uint256 limit)
        external
        view
        returns (address[] memory addresses, uint256 total)
    {
        total = participants.length();

        if (offset >= total) {
            return (new address[](0), total);
        }

        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }

        uint256 length = end - offset;
        addresses = new address[](length);

        for (uint256 i = 0; i < length; i++) {
            addresses[i] = participants.at(offset + i);
        }

        return (addresses, total);
    }

    /// @notice Get distribution status
    /// @return inProgress Whether distribution is in progress
    /// @return currentIndex Current processing index
    /// @return totalParticipants Total number of participants
    /// @return amountPerParticipant Amount per participant in current distribution
    function getDistributionStatus()
        external
        view
        returns (bool inProgress, uint256 currentIndex, uint256 totalParticipants, uint256 amountPerParticipant)
    {
        return (distributionInProgress, currentDistributionIndex, participants.length(), pendingDistributionAmount);
    }

    /// @notice Check if address is participant (O(1) lookup)
    /// @param participant Address to check
    /// @return Whether address is a participant
    function isParticipant(address participant) external view returns (bool) {
        return participants.contains(participant);
    }

    /// @notice Get participant count (O(1) operation)
    /// @return Number of participants
    function getParticipantCount() external view returns (uint256) {
        return participants.length();
    }

    /// @notice Get participant balance
    /// @param participant Address to check
    /// @return balance Current claimable balance
    /// @return claimed Total amount claimed historically
    function getParticipantInfo(address participant) external view returns (uint256 balance, uint256 claimed) {
        return (balances[participant], totalClaimed[participant]);
    }

    /// @notice Get contract financial summary
    /// @return contractBalance Current contract balance
    /// @return totalRewardsAvailable Available rewards for distribution
    /// @return totalDistributedAmount Total amount distributed historically
    function getFinancialSummary()
        external
        view
        returns (uint256 contractBalance, uint256 totalRewardsAvailable, uint256 totalDistributedAmount)
    {
        return (address(this).balance, totalRewards, totalDistributed);
    }

    /// @notice Emergency withdrawal (owner only)
    /// @dev Only callable when no distribution is in progress
    function emergencyWithdraw() external onlyOwner noDistributionInProgress nonReentrant {
        uint256 contractBalance = address(this).balance;
        if (contractBalance == 0) revert NoRewardsAvailable();

        (bool success,) = payable(owner()).call{value: contractBalance}("");
        require(success, "Emergency withdrawal failed");
    }

    /// @notice Estimate gas for full distribution
    /// @return estimatedGas Estimated gas needed for complete distribution
    /// @return batchesNeeded Number of continueDistribution() calls needed
    function estimateDistributionGas() external view returns (uint256 estimatedGas, uint256 batchesNeeded) {
        uint256 participantCount = participants.length();
        batchesNeeded = (participantCount + MAX_PARTICIPANTS_PER_TX - 1) / MAX_PARTICIPANTS_PER_TX;

        // Rough estimate: ~30k gas per participant for balance update
        estimatedGas = participantCount * 30000;

        return (estimatedGas, batchesNeeded);
    }
}
