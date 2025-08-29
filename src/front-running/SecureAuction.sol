// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title SecureAuction - An auction contract with front-running protection mechanisms
/// @notice This contract demonstrates various techniques to mitigate front-running attacks
/// @dev Uses commit-reveal scheme and other anti-MEV techniques
contract SecureAuction is ReentrancyGuard, Ownable {
    enum Phase {
        Commit,
        Reveal,
        Ended
    }

    struct CommittedBid {
        bytes32 commitment;
        uint256 deposit;
        bool revealed;
    }

    Phase public currentPhase;
    uint256 public commitEndTime;
    uint256 public revealEndTime;
    uint256 public auctionEndTime;

    address public highestBidder;
    uint256 public highestBid;
    uint256 public reservePrice;

    mapping(address => CommittedBid) public committedBids;
    mapping(address => uint256) public pendingReturns;

    bool public ended;

    event CommitPlaced(address indexed bidder, bytes32 commitment, uint256 deposit);
    event BidRevealed(address indexed bidder, uint256 bidAmount, uint256 nonce);
    event AuctionEnded(address indexed winner, uint256 amount);
    event BidWithdrawn(address indexed bidder, uint256 amount);
    event PhaseChanged(Phase newPhase);

    error InvalidPhase();
    error CommitmentAlreadyExists();
    error InsufficientDeposit();
    error InvalidReveal();
    error NoCommitmentFound();
    error AuctionNotEnded();
    error ReservePriceNotMet();
    error UnauthorizedAccess();

    modifier inPhase(Phase phase) {
        if (currentPhase != phase) revert InvalidPhase();
        _;
    }

    modifier onlyAfterReveal() {
        require(block.timestamp > revealEndTime, "Reveal phase not ended");
        _;
    }

    constructor(uint256 _commitDuration, uint256 _revealDuration, uint256 _reservePrice) Ownable(msg.sender) {
        commitEndTime = block.timestamp + _commitDuration;
        revealEndTime = commitEndTime + _revealDuration;
        auctionEndTime = revealEndTime;
        reservePrice = _reservePrice;
        currentPhase = Phase.Commit;
    }

    /// @notice Commit to a bid using hash commitment (ANTI-FRONT-RUNNING)
    /// @param commitment Hash of bid amount, nonce, and bidder address
    /// @dev Prevents front-running by hiding actual bid amounts during commit phase
    function commitBid(bytes32 commitment) external payable inPhase(Phase.Commit) nonReentrant {
        require(commitment != bytes32(0), "Invalid commitment");
        if (committedBids[msg.sender].commitment != bytes32(0)) {
            revert CommitmentAlreadyExists();
        }
        if (msg.value < 0.01 ether) {
            revert InsufficientDeposit(); // Minimum deposit to prevent spam
        }

        committedBids[msg.sender] = CommittedBid({commitment: commitment, deposit: msg.value, revealed: false});

        emit CommitPlaced(msg.sender, commitment, msg.value);
    }

    /// @notice Generate commitment hash for bidding
    /// @param bidAmount Bid amount in wei
    /// @param nonce Random number for security
    /// @param bidder Bidder address
    /// @return Hash commitment
    function generateCommitment(uint256 bidAmount, uint256 nonce, address bidder) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(bidAmount, nonce, bidder));
    }

    /// @notice Reveal committed bid (SECURE REVEAL MECHANISM)
    /// @param bidAmount Actual bid amount
    /// @param nonce Random nonce used in commitment
    function revealBid(uint256 bidAmount, uint256 nonce) external payable inPhase(Phase.Reveal) nonReentrant {
        CommittedBid storage committedBid = committedBids[msg.sender];

        if (committedBid.commitment == bytes32(0)) {
            revert NoCommitmentFound();
        }

        require(!committedBid.revealed, "Bid already revealed");

        // SECURITY: Verify commitment matches revealed values
        bytes32 expectedCommitment = generateCommitment(bidAmount, nonce, msg.sender);
        if (committedBid.commitment != expectedCommitment) {
            revert InvalidReveal();
        }

        // SECURITY: Ensure bidder sent enough ether to cover their bid
        uint256 totalDeposit = committedBid.deposit + msg.value;
        require(totalDeposit >= bidAmount, "Insufficient ether for bid");

        committedBid.revealed = true;

        // Update highest bid if this bid is higher
        if (bidAmount > highestBid && bidAmount >= reservePrice) {
            // Return previous highest bidder's funds to pending returns
            if (highestBidder != address(0)) {
                pendingReturns[highestBidder] += highestBid;
            }

            highestBidder = msg.sender;
            highestBid = bidAmount;
        }

        // Calculate refund (deposit + additional payment - winning bid or 0 if lost)
        uint256 refund = totalDeposit;
        if (msg.sender == highestBidder) {
            refund = totalDeposit - bidAmount;
        }

        if (refund > 0) {
            pendingReturns[msg.sender] += refund;
        }

        emit BidRevealed(msg.sender, bidAmount, nonce);
    }

    /// @notice Advance to next phase (owner only for security)
    function advancePhase() external onlyOwner {
        if (currentPhase == Phase.Commit && block.timestamp >= commitEndTime) {
            currentPhase = Phase.Reveal;
            emit PhaseChanged(Phase.Reveal);
        } else if (currentPhase == Phase.Reveal && block.timestamp >= revealEndTime) {
            currentPhase = Phase.Ended;
            emit PhaseChanged(Phase.Ended);
        } else {
            revert("Cannot advance phase yet");
        }
    }

    /// @notice End auction and finalize results (SECURE FINALIZATION)
    function endAuction() external onlyAfterReveal nonReentrant {
        require(!ended, "Auction already ended");
        require(currentPhase == Phase.Ended, "Auction not in ended phase");

        ended = true;

        if (highestBidder == address(0) || highestBid < reservePrice) {
            emit AuctionEnded(address(0), 0);
            return;
        }

        emit AuctionEnded(highestBidder, highestBid);

        // Transfer winning bid to seller (owner)
        (bool success,) = payable(owner()).call{value: highestBid}("");
        require(success, "Transfer to seller failed");
    }

    /// @notice Withdraw pending returns
    function withdraw() external nonReentrant {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No funds to withdraw");

        pendingReturns[msg.sender] = 0;

        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "Withdrawal failed");

        emit BidWithdrawn(msg.sender, amount);
    }

    /// @notice Withdraw unrevealed deposits (after reveal phase)
    /// @dev Allows recovery of deposits for bids that were never revealed
    function withdrawUnrevealedDeposit() external {
        require(currentPhase == Phase.Ended, "Auction not ended");

        CommittedBid storage committedBid = committedBids[msg.sender];
        require(committedBid.commitment != bytes32(0), "No commitment found");
        require(!committedBid.revealed, "Bid was already revealed");
        require(committedBid.deposit > 0, "No deposit to withdraw");

        uint256 deposit = committedBid.deposit;
        committedBid.deposit = 0;

        (bool success,) = payable(msg.sender).call{value: deposit}("");
        require(success, "Deposit withdrawal failed");

        emit BidWithdrawn(msg.sender, deposit);
    }

    /// @notice Emergency function to extend phases (owner only)
    /// @param additionalCommitTime Additional commit time in seconds
    /// @param additionalRevealTime Additional reveal time in seconds
    function extendPhases(uint256 additionalCommitTime, uint256 additionalRevealTime) external onlyOwner {
        require(!ended, "Auction already ended");
        require(additionalCommitTime > 0 || additionalRevealTime > 0, "No extension specified");

        if (additionalCommitTime > 0) {
            commitEndTime += additionalCommitTime;
            revealEndTime += additionalCommitTime;
        }

        if (additionalRevealTime > 0) {
            revealEndTime += additionalRevealTime;
        }

        auctionEndTime = revealEndTime;
    }

    /// @notice Set reserve price (owner only, before auction ends)
    /// @param newReservePrice New reserve price
    function setReservePrice(uint256 newReservePrice) external onlyOwner {
        require(!ended, "Auction already ended");
        require(currentPhase == Phase.Commit, "Can only change during commit phase");

        reservePrice = newReservePrice;
    }

    /// @notice Get auction timing information
    /// @return commitEnd Commit phase end time
    /// @return revealEnd Reveal phase end time
    /// @return currentTime Current block timestamp
    /// @return phase Current auction phase
    function getAuctionTiming()
        external
        view
        returns (uint256 commitEnd, uint256 revealEnd, uint256 currentTime, Phase phase)
    {
        return (commitEndTime, revealEndTime, block.timestamp, currentPhase);
    }

    /// @notice Get commitment info for a bidder
    /// @param bidder Bidder address
    /// @return commitment Hash commitment
    /// @return deposit Deposit amount
    /// @return revealed Whether bid was revealed
    function getCommitmentInfo(address bidder)
        external
        view
        returns (bytes32 commitment, uint256 deposit, bool revealed)
    {
        CommittedBid memory bid = committedBids[bidder];
        return (bid.commitment, bid.deposit, bid.revealed);
    }

    /// @notice Get current auction state
    /// @return seller_ Auction seller
    /// @return highestBidder_ Current highest bidder
    /// @return highestBid_ Current highest bid
    /// @return reservePrice_ Reserve price
    /// @return ended_ Whether auction ended
    function getAuctionState()
        external
        view
        returns (address seller_, address highestBidder_, uint256 highestBid_, uint256 reservePrice_, bool ended_)
    {
        return (owner(), highestBidder, highestBid, reservePrice, ended);
    }

    /// @notice Check if auction is in active phase
    /// @return Whether auction is active (commit or reveal phase)
    function isActive() external view returns (bool) {
        return currentPhase != Phase.Ended && !ended;
    }

    /// @notice Get time remaining in current phase
    /// @return Time remaining in seconds
    function getTimeRemainingInPhase() external view returns (uint256) {
        if (currentPhase == Phase.Commit) {
            if (block.timestamp >= commitEndTime) return 0;
            return commitEndTime - block.timestamp;
        } else if (currentPhase == Phase.Reveal) {
            if (block.timestamp >= revealEndTime) return 0;
            return revealEndTime - block.timestamp;
        }
        return 0;
    }

    /// @notice Get pending return amount for bidder
    /// @param bidder Bidder address
    /// @return Amount available for withdrawal
    function getPendingReturn(address bidder) external view returns (uint256) {
        return pendingReturns[bidder];
    }
}
