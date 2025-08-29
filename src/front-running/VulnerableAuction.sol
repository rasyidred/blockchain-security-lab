// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @title VulnerableAuction - An auction contract vulnerable to front-running attacks
/// @notice This contract demonstrates front-running vulnerabilities in auction mechanisms
/// @dev WARNING: This contract is intentionally vulnerable for educational purposes
contract VulnerableAuction {
    address public seller;
    address public highestBidder;
    uint256 public highestBid;
    uint256 public auctionEndTime;
    bool public ended;

    mapping(address => uint256) public pendingReturns;

    event BidPlaced(address indexed bidder, uint256 amount);
    event AuctionEnded(address indexed winner, uint256 amount);
    event BidWithdrawn(address indexed bidder, uint256 amount);

    modifier onlyBeforeEnd() {
        require(block.timestamp <= auctionEndTime, "Auction already ended");
        _;
    }

    modifier onlyAfterEnd() {
        require(block.timestamp > auctionEndTime, "Auction not yet ended");
        _;
    }

    constructor(uint256 _biddingTime) {
        seller = msg.sender;
        auctionEndTime = block.timestamp + _biddingTime;
    }

    /// @notice Place a bid (VULNERABLE TO FRONT-RUNNING)
    /// @dev Anyone can see pending bids and front-run with higher bids
    function bid() external payable onlyBeforeEnd {
        require(msg.value > highestBid, "Bid not high enough");

        if (highestBidder != address(0)) {
            // Return the previous highest bid
            pendingReturns[highestBidder] += highestBid;
        }

        // VULNERABILITY: All bid information is public, enabling front-running
        highestBidder = msg.sender;
        highestBid = msg.value;

        emit BidPlaced(msg.sender, msg.value);
    }

    /// @notice Reveal the current highest bid (ENABLES FRONT-RUNNING)
    /// @dev This function makes it easy for attackers to see current highest bid
    /// @return currentHighestBidder Current highest bidder
    /// @return currentHighestBid Current highest bid amount
    function getCurrentHighestBid() external view returns (address currentHighestBidder, uint256 currentHighestBid) {
        return (highestBidder, highestBid);
    }

    /// @notice Get pending bid amount for withdrawal
    /// @param bidder Bidder address
    /// @return amount Amount available for withdrawal
    function getPendingReturn(address bidder) external view returns (uint256 amount) {
        return pendingReturns[bidder];
    }

    /// @notice Withdraw overbid funds
    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "No funds to withdraw");

        pendingReturns[msg.sender] = 0;

        (bool success,) = payable(msg.sender).call{value: amount}("");
        require(success, "Withdrawal failed");

        emit BidWithdrawn(msg.sender, amount);
    }

    /// @notice End the auction and transfer funds to seller (VULNERABLE)
    /// @dev Anyone can call this after auction ends
    function endAuction() external onlyAfterEnd {
        require(!ended, "Auction already ended");

        ended = true;
        emit AuctionEnded(highestBidder, highestBid);

        // VULNERABILITY: Direct transfer without proper access control
        if (highestBidder != address(0)) {
            (bool success,) = payable(seller).call{value: highestBid}("");
            require(success, "Transfer to seller failed");
        }
    }

    /// @notice Emergency function to extend auction (VULNERABLE)
    /// @param additionalTime Additional time in seconds
    /// @dev Only seller should be able to call this, but no access control
    function extendAuction(uint256 additionalTime) external {
        require(!ended, "Auction already ended");
        require(additionalTime > 0, "Additional time must be positive");

        // VULNERABILITY: No access control - anyone can extend auction
        auctionEndTime += additionalTime;
    }

    /// @notice Place multiple bids at once (VULNERABLE TO MEV)
    /// @param bidAmounts Array of bid amounts
    /// @dev Allows batching multiple bids, vulnerable to sandwich attacks
    function batchBid(uint256[] calldata bidAmounts) external payable onlyBeforeEnd {
        uint256 totalValue = 0;
        for (uint256 i = 0; i < bidAmounts.length; i++) {
            totalValue += bidAmounts[i];
        }
        require(msg.value >= totalValue, "Insufficient ether sent");

        // VULNERABILITY: Sequential bids can be front-run or sandwich attacked
        for (uint256 i = 0; i < bidAmounts.length; i++) {
            if (bidAmounts[i] > highestBid) {
                if (highestBidder != address(0)) {
                    pendingReturns[highestBidder] += highestBid;
                }
                highestBidder = msg.sender;
                highestBid = bidAmounts[i];
                emit BidPlaced(msg.sender, bidAmounts[i]);
            }
        }

        // Return excess ether
        uint256 excess = msg.value - totalValue;
        if (excess > 0) {
            pendingReturns[msg.sender] += excess;
        }
    }

    /// @notice Set reserve price (VULNERABLE - no access control)
    /// @param reservePrice Minimum price for auction
    function setReservePrice(uint256 reservePrice) external {
        require(!ended, "Auction already ended");

        // VULNERABILITY: Anyone can change reserve price
        if (reservePrice > highestBid) {
            highestBid = reservePrice;
        }
    }

    /// @notice Quick bid function (VULNERABLE TO FRONT-RUNNING)
    /// @dev Automatically bids slightly higher than current highest bid
    function quickBid() external payable onlyBeforeEnd {
        // VULNERABILITY: Uses predictable bid increment, easy to front-run
        uint256 minimumBid = highestBid + 0.01 ether;
        require(msg.value >= minimumBid, "Bid too low");

        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;

        emit BidPlaced(msg.sender, msg.value);
    }

    /// @notice Snipe bid in final seconds (VULNERABLE)
    /// @dev Allows last-second bidding, vulnerable to front-running
    function snipeBid() external payable {
        require(block.timestamp <= auctionEndTime + 10, "Snipe window closed");
        require(msg.value > highestBid, "Bid not high enough");

        // VULNERABILITY: Extends auction automatically, can be exploited
        if (block.timestamp > auctionEndTime) {
            auctionEndTime = block.timestamp + 60; // Extend by 1 minute
        }

        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;

        emit BidPlaced(msg.sender, msg.value);
    }

    /// @notice Get auction info
    /// @return seller_ Seller address
    /// @return highestBidder_ Current highest bidder
    /// @return highestBid_ Current highest bid
    /// @return auctionEndTime_ Auction end time
    /// @return ended_ Whether auction has ended
    function getAuctionInfo()
        external
        view
        returns (address seller_, address highestBidder_, uint256 highestBid_, uint256 auctionEndTime_, bool ended_)
    {
        return (seller, highestBidder, highestBid, auctionEndTime, ended);
    }

    /// @notice Check if auction is active
    /// @return Whether auction is currently active
    function isActive() external view returns (bool) {
        return block.timestamp <= auctionEndTime && !ended;
    }

    /// @notice Get time remaining in auction
    /// @return Time remaining in seconds (0 if ended)
    function getTimeRemaining() external view returns (uint256) {
        if (block.timestamp >= auctionEndTime) {
            return 0;
        }
        return auctionEndTime - block.timestamp;
    }
}
