// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title VulnerableDistributor - A contract vulnerable to Denial of Service attacks
/// @notice This contract demonstrates various DOS vulnerabilities in reward distribution
/// @dev WARNING: This contract is intentionally vulnerable for educational purposes
contract VulnerableDistributor {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isParticipant;
    address[] public participants;

    uint256 public totalRewards;
    uint256 public rewardPerParticipant;
    bool public distributionActive;

    event RewardDeposited(address indexed depositor, uint256 amount);
    event ParticipantAdded(address indexed participant);
    event RewardsDistributed(uint256 totalAmount, uint256 participantCount);
    event RewardClaimed(address indexed participant, uint256 amount);
    event DistributionFailed(address indexed participant, bytes reason);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Add participant to reward distribution
    /// @param participant Address to add as participant
    function addParticipant(address participant) external onlyOwner {
        require(participant != address(0), "Invalid address");
        require(!isParticipant[participant], "Already a participant");

        participants.push(participant);
        isParticipant[participant] = true;

        emit ParticipantAdded(participant);
    }

    /// @notice Batch add multiple participants (VULNERABLE TO DOS)
    /// @param newParticipants Array of addresses to add
    /// @dev Unbounded loop can cause out-of-gas errors
    function batchAddParticipants(address[] calldata newParticipants) external onlyOwner {
        // VULNERABILITY: No limit on array size, can cause out-of-gas
        for (uint256 i = 0; i < newParticipants.length; i++) {
            require(newParticipants[i] != address(0), "Invalid address");
            require(!isParticipant[newParticipants[i]], "Already a participant");

            participants.push(newParticipants[i]);
            isParticipant[newParticipants[i]] = true;

            emit ParticipantAdded(newParticipants[i]);
        }
    }

    /// @notice Deposit rewards for distribution
    function depositRewards() external payable {
        require(msg.value > 0, "Must send ether");
        totalRewards += msg.value;
        emit RewardDeposited(msg.sender, msg.value);
    }

    /// @notice Distribute rewards to all participants (VULNERABLE TO DOS)
    /// @dev Unbounded loop iterating through all participants
    function distributeRewards() external onlyOwner {
        require(totalRewards > 0, "No rewards to distribute");
        require(participants.length > 0, "No participants");

        rewardPerParticipant = totalRewards / participants.length;
        distributionActive = true;

        // VULNERABILITY: Unbounded loop - can run out of gas with many participants
        for (uint256 i = 0; i < participants.length; i++) {
            balances[participants[i]] += rewardPerParticipant;
        }

        emit RewardsDistributed(totalRewards, participants.length);
        totalRewards = 0;
    }

    /// @notice Push rewards directly to participants (HIGHLY VULNERABLE)
    /// @dev Calls external contracts, vulnerable to revert attacks
    function pushRewardsToAll() external onlyOwner {
        require(totalRewards > 0, "No rewards to distribute");
        require(participants.length > 0, "No participants");

        uint256 rewardAmount = totalRewards / participants.length;

        // VULNERABILITY: One failing transfer can block entire distribution
        for (uint256 i = 0; i < participants.length; i++) {
            (bool success,) = payable(participants[i]).call{value: rewardAmount}("");
            require(success, "Transfer failed");

            emit RewardClaimed(participants[i], rewardAmount);
        }

        totalRewards = 0;
        emit RewardsDistributed(totalRewards, participants.length);
    }

    /// @notice Alternative push rewards that continues on failure (STILL VULNERABLE)
    /// @dev Consumes gas even when transfers fail
    function pushRewardsContinueOnFailure() external onlyOwner {
        require(totalRewards > 0, "No rewards to distribute");
        require(participants.length > 0, "No participants");

        uint256 rewardAmount = totalRewards / participants.length;

        // VULNERABILITY: Still vulnerable to gas exhaustion with many participants
        for (uint256 i = 0; i < participants.length; i++) {
            (bool success, bytes memory returnData) = payable(participants[i]).call{value: rewardAmount}("");

            if (success) {
                emit RewardClaimed(participants[i], rewardAmount);
            } else {
                emit DistributionFailed(participants[i], returnData);
                // Keep reward for manual claiming
                balances[participants[i]] += rewardAmount;
            }
        }

        totalRewards = 0;
        emit RewardsDistributed(totalRewards, participants.length);
    }

    /// @notice Get all participants (VULNERABLE TO DOS)
    /// @return Array of all participant addresses
    /// @dev Can cause out-of-gas if participants array is very large
    function getAllParticipants() external view returns (address[] memory) {
        // VULNERABILITY: Returning large array can exceed gas limit
        return participants;
    }

    /// @notice Calculate total owed to all participants (VULNERABLE)
    /// @return Total amount owed across all participants
    function getTotalOwed() external view returns (uint256) {
        uint256 total = 0;

        // VULNERABILITY: Unbounded loop can cause out-of-gas
        for (uint256 i = 0; i < participants.length; i++) {
            total += balances[participants[i]];
        }

        return total;
    }

    /// @notice Remove participant (VULNERABLE - requires iteration)
    /// @param participant Address to remove
    function removeParticipant(address participant) external onlyOwner {
        require(isParticipant[participant], "Not a participant");

        // VULNERABILITY: O(n) operation to find and remove participant
        for (uint256 i = 0; i < participants.length; i++) {
            if (participants[i] == participant) {
                participants[i] = participants[participants.length - 1];
                participants.pop();
                break;
            }
        }

        isParticipant[participant] = false;
        // Note: Don't reset balance - allow withdrawal
    }

    /// @notice Clear all participants (VULNERABLE TO DOS)
    /// @dev Expensive operation that grows with participants count
    function clearAllParticipants() external onlyOwner {
        // VULNERABILITY: Expensive operation, can run out of gas
        for (uint256 i = 0; i < participants.length; i++) {
            isParticipant[participants[i]] = false;
        }
        delete participants;
    }

    /// @notice Claim individual reward (Safe pull pattern)
    function claimReward() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No rewards to claim");

        balances[msg.sender] = 0;

        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");

        emit RewardClaimed(msg.sender, amount);
    }

    /// @notice Mass payout with gas limit check (STILL VULNERABLE)
    /// @param gasLimit Maximum gas to use per transfer
    function massPayoutWithGasLimit(uint256 gasLimit) external onlyOwner {
        require(totalRewards > 0, "No rewards to distribute");
        require(participants.length > 0, "No participants");

        uint256 rewardAmount = totalRewards / participants.length;
        uint256 gasUsed = 0;
        uint256 gasStart = gasleft();

        // VULNERABILITY: Can still be manipulated by malicious participants
        for (uint256 i = 0; i < participants.length; i++) {
            if (gasUsed >= gasLimit) {
                break; // Stop if gas limit reached
            }

            (bool success,) = payable(participants[i]).call{gas: 2300, value: rewardAmount}("");

            if (success) {
                emit RewardClaimed(participants[i], rewardAmount);
            } else {
                balances[participants[i]] += rewardAmount;
                emit DistributionFailed(participants[i], "Transfer failed");
            }

            gasUsed = gasStart - gasleft();
        }

        totalRewards = 0;
    }

    /// @notice Withdraw contract funds (emergency)
    function emergencyWithdraw() external onlyOwner {
        uint256 contractBalance = address(this).balance;
        (bool success,) = payable(owner).call{value: contractBalance}("");
        require(success, "Withdrawal failed");
    }

    /// @notice Get participant count
    /// @return Number of participants
    function getParticipantCount() external view returns (uint256) {
        return participants.length;
    }

    /// @notice Get participant balance
    /// @param participant Address to check
    /// @return Balance of participant
    function getParticipantBalance(address participant) external view returns (uint256) {
        return balances[participant];
    }

    /// @notice Check if address is participant
    /// @param participant Address to check
    /// @return Whether address is a participant
    function checkParticipant(address participant) external view returns (bool) {
        return isParticipant[participant];
    }

    /// @notice Get contract balance
    /// @return Current contract balance
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
