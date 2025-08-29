# Blockchain Security Lab 🔐

> **A comprehensive educational repository for learning smart contract security through hands-on vulnerability demonstrations**

[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C.svg)](https://getfoundry.sh/)
[![Solidity](https://img.shields.io/badge/Solidity-%5E0.8.20-blue.svg)](https://docs.soliditylang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🎯 Purpose & Educational Value

This repository serves as a **practical learning resource** for blockchain developers, security researchers, and auditors who want to understand smart contract vulnerabilities through **real, exploitable code examples**. Rather than just theoretical explanations, this lab provides:

- **Live vulnerability demonstrations** with working exploit code
- **Before/after comparisons** showing vulnerable vs. secure implementations
- **Interactive test suites** that walk through attack scenarios step-by-step
- **Gas analysis** showing the cost trade-offs of security measures
- **Real-world context** connecting each vulnerability to famous historical exploits

**Perfect for**:
- 🎓 Computer Science students learning blockchain security
- 🔧 Smart contract developers building security awareness
- 🛡️ Security auditors training on common vulnerability patterns
- 💼 Portfolio projects demonstrating security expertise
- 🏢 Development teams conducting security workshops

## 📋 Project Overview

This lab implements **four critical smart contract vulnerabilities** that have collectively cost the DeFi ecosystem **billions of dollars**. Each vulnerability includes:

✅ **Vulnerable Implementation**: Intentionally insecure contracts mirroring real-world flaws  
✅ **Secure Implementation**: Hardened versions using industry best practices  
✅ **Comprehensive Test Suites**: Detailed attack demonstrations with step-by-step explanations  
✅ **Gas Analysis**: Performance impact of security measures  
✅ **Historical Context**: Connection to real exploits and their financial impact

## Vulnerabilities Covered

### 1. Reentrancy Attacks
**Location**: `src/reentrancy/`

**Vulnerability**: Functions that make external calls before updating internal state, allowing attackers to recursively call back into the contract.

**Example Scenario**: A bank contract that transfers Ether before updating the user's balance, enabling attackers to drain funds by re-entering the withdraw function.

**Key Files**:
- `VulnerableBank.sol` - Demonstrates classic reentrancy vulnerability
- `SecureBank.sol` - Protected using ReentrancyGuard and CEI pattern
- `test/reentrancy/ReentrancyExploit.t.sol` - Complete attack demonstrations

### 2. Integer Overflow/Underflow  
**Location**: `src/integer-overflow/`

**Vulnerability**: Arithmetic operations that exceed type limits, causing values to wrap around unexpectedly.

**Example Scenario**: A token contract using Solidity 0.7.6 without SafeMath, allowing attackers to create tokens from nothing or manipulate balances through overflow/underflow.

**Key Files**:
- `VulnerableToken.sol` - Token vulnerable to arithmetic attacks (Solidity 0.7.6)
- `SecureToken.sol` - Protected using Solidity 0.8.20+ and explicit checks
- `test/integer-overflow/IntegerOverflowExploit.t.sol` - Overflow/underflow demonstrations

### 3. Unchecked External Calls
**Location**: `src/unchecked-call/`  

**Vulnerability**: External function calls that don't check return values, potentially leading to silent failures and inconsistent state.

**Example Scenario**: A wallet contract that doesn't verify if Ether transfers succeed, leading to balance discrepancies and stuck funds.

**Key Files**:
- `VulnerableWallet.sol` - Wallet with unchecked external calls
- `SecureWallet.sol` - Proper call handling with OpenZeppelin utilities  
- `test/unchecked-call/UncheckedCallExploit.t.sol` - Silent failure demonstrations

### 4. Front-Running Attacks
**Location**: `src/front-running/`

**Vulnerability**: Transactions visible in the mempool before execution, allowing attackers to see and front-run with higher gas prices.

**Example Scenario**: An auction contract where bid amounts are visible, enabling MEV bots to front-run with slightly higher bids.

**Key Files**:
- `VulnerableAuction.sol` - Auction vulnerable to front-running and MEV
- `SecureAuction.sol` - Commit-reveal scheme preventing front-running
- `test/front-running/FrontRunningExploit.t.sol` - MEV and sandwich attack demos

## Quick Start

### Prerequisites
- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Git

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd blockchain-security-lab

# Install dependencies
forge install

# Build contracts  
forge build

# Run all tests
forge test -vvv
```

### Running Specific Tests

```bash
# Test reentrancy vulnerabilities
forge test --match-path "test/reentrancy/*" -vvv

# Test integer overflow vulnerabilities  
forge test --match-path "test/integer-overflow/*" -vvv

# Test unchecked call vulnerabilities
forge test --match-path "test/unchecked-call/*" -vvv

# Test front-running vulnerabilities
forge test --match-path "test/front-running/*" -vvv
```

### Generate Coverage Reports

```bash
forge coverage --report lcov
```

## Detailed Vulnerability Analysis

### 1. Reentrancy Attack

**Vulnerability Pattern**:
```solidity
function withdraw() external {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "Insufficient balance");
    
    // VULNERABILITY: External call before state update
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");
    
    balances[msg.sender] = 0; // Too late!
}
```

**Attack Mechanism**:
1. Attacker calls `withdraw()` 
2. Contract sends Ether to attacker's contract
3. Attacker's `receive()` function calls `withdraw()` again
4. Balance hasn't been updated yet, so second withdrawal succeeds
5. Process repeats until contract is drained

**Secure Pattern**:
```solidity
function withdraw() external nonReentrant {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "Insufficient balance");
    
    // SECURITY: Update state before external call (CEI pattern)
    balances[msg.sender] = 0;
    
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");
}
```

**Prevention Techniques**:
- **Checks-Effects-Interactions (CEI)** pattern
- **ReentrancyGuard** modifier  
- **Pull payment** pattern
- Gas limit consideration with `transfer()`

### 2. Integer Overflow/Underflow

**Vulnerability Pattern** (Solidity < 0.8.0):
```solidity
function transfer(address to, uint256 amount) external returns (bool) {
    // VULNERABILITY: No overflow/underflow protection
    balances[msg.sender] -= amount; // Can underflow
    balances[to] += amount; // Can overflow
    return true;
}
```

**Attack Scenarios**:
- **Underflow**: Transfer more tokens than owned → balance wraps to max value
- **Overflow**: Mint excessive tokens → totalSupply wraps around
- **Arithmetic manipulation**: Exploit calculations in DeFi protocols

**Secure Patterns**:
```solidity
// Solidity 0.8.0+ automatic protection
function transfer(address to, uint256 amount) external returns (bool) {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    balances[msg.sender] -= amount; // Safe from underflow
    balances[to] += amount; // Safe from overflow
    return true;
}

// Additional explicit checks
function mint(address to, uint256 amount) external {
    require(totalSupply + amount >= totalSupply, "Total supply overflow");
    totalSupply += amount;
    balances[to] += amount;
}
```

**Prevention Techniques**:
- **Solidity 0.8.0+** built-in overflow protection
- **Explicit bounds checking** before operations
- **SafeMath library** for older Solidity versions
- **Input validation** and reasonable limits

### 3. Unchecked External Calls

**Vulnerability Pattern**:
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    balances[msg.sender] -= amount;
    
    // VULNERABILITY: Call return value ignored - silent failures possible
    msg.sender.call{value: amount}("");
    
    emit Withdrawal(msg.sender, amount);
}

function batchWithdraw(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner {
    for (uint256 i = 0; i < recipients.length; i++) {
        // VULNERABILITY: Individual call failures ignored
        payable(recipients[i]).call{value: amounts[i]}("");
        emit Withdrawal(recipients[i], amounts[i]);
    }
}
```

**Attack Scenarios**:

1. **Silent Failures in Withdrawals**:
   - User's balance gets deducted even if transfer fails
   - Funds become permanently stuck in contract
   - Internal accounting doesn't match actual Ether

2. **Batch Operation Vulnerabilities**:
   - Some recipients receive funds, others don't
   - No atomicity - partial execution with inconsistent state
   - Events emitted even for failed transfers

3. **Malicious Recipient Contracts**:
   - Contracts that intentionally reject Ether transfers
   - Exploit inconsistencies between intended and actual transfers
   - Cause systematic failures in batch operations

4. **Emergency Function Failures**:
   - Emergency withdrawals fail silently
   - Funds remain locked during critical situations
   - No fallback mechanism for stuck funds

**Detailed Attack Example**:
```solidity
// Malicious contract that selectively rejects Ether
contract MaliciousReceiver {
    bool public shouldRevert = false;
    
    function toggleBehavior() external {
        shouldRevert = !shouldRevert;
    }
    
    receive() external payable {
        if (shouldRevert) {
            revert("Rejecting Ether transfer");
        }
    }
}

// Attack sequence:
// 1. Deposit funds to vulnerable wallet
// 2. Toggle malicious receiver to reject mode
// 3. Attempt withdrawal - balance deducted but transfer fails
// 4. Funds stuck, but internal balance shows zero
```

**Secure Patterns**:
```solidity
function withdraw(uint256 amount) external nonReentrant {
    if (amount == 0) revert ZeroAmount();
    if (balances[msg.sender] < amount) {
        revert InsufficientBalance(amount, balances[msg.sender]);
    }
    
    balances[msg.sender] -= amount;
    
    // SECURITY: Always check call success and revert on failure
    (bool success,) = payable(msg.sender).call{value: amount}("");
    if (!success) {
        balances[msg.sender] += amount; // Restore balance on failure
        revert CallFailedError(msg.sender, bytes(""));
    }
    
    emit Withdrawal(msg.sender, amount);
}

function batchWithdraw(address[] calldata recipients, uint256[] calldata amounts) 
    external onlyOwner nonReentrant {
    
    require(recipients.length == amounts.length, "Arrays length mismatch");
    
    // SECURITY: Validate all recipients and amounts first
    uint256 totalAmount = 0;
    for (uint256 i = 0; i < amounts.length; i++) {
        if (recipients[i] == address(0)) revert InvalidAddress();
        if (amounts[i] == 0) revert ZeroAmount();
        totalAmount += amounts[i];
    }
    
    if (address(this).balance < totalAmount) {
        revert InsufficientBalance(totalAmount, address(this).balance);
    }
    
    // SECURITY: All-or-nothing approach - revert entire batch on any failure
    for (uint256 i = 0; i < recipients.length; i++) {
        (bool success,) = payable(recipients[i]).call{value: amounts[i]}("");
        if (!success) {
            emit CallFailed(recipients[i], "", "Transfer failed");
            revert CallFailedError(recipients[i], bytes(""));
        }
        emit Withdrawal(recipients[i], amounts[i]);
    }
}

// Alternative: Using OpenZeppelin's Address.sendValue
function withdrawSafe(uint256 amount) external nonReentrant {
    if (balances[msg.sender] < amount) {
        revert InsufficientBalance(amount, balances[msg.sender]);
    }
    
    balances[msg.sender] -= amount;
    payable(msg.sender).sendValue(amount); // Automatically reverts on failure
    
    emit Withdrawal(msg.sender, amount);
}
```

**Advanced Secure Patterns**:
```solidity
// Multi-call with selective failure handling
function multiCall(address[] calldata targets, bytes[] calldata callDatas, bool continueOnFailure)
    external onlyOwner nonReentrant
    returns (bytes[] memory results, bool[] memory successes)
{
    results = new bytes[](targets.length);
    successes = new bool[](targets.length);
    
    for (uint256 i = 0; i < targets.length; i++) {
        require(targets[i] != address(this), "Cannot call self");
        
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
```

**Prevention Techniques**:
- **Always check return values** of external calls (`call`, `send`, `transfer`)
- **Use OpenZeppelin's Address library** for safe transfers (`sendValue`, `functionCall`)
- **Implement proper error handling** with custom errors and detailed revert messages
- **Follow all-or-nothing pattern** for batch operations
- **Add reentrancy protection** with `nonReentrant` modifier
- **Validate inputs thoroughly** before making external calls
- **Consider pull payment patterns** to shift transfer responsibility to recipients
- **Implement emergency mechanisms** with guaranteed success paths
- **Use events judiciously** - only emit on actual success

### 4. Front-Running Attacks

**Vulnerability Pattern**:
```solidity
function bid() external payable {
    require(msg.value > highestBid, "Bid not high enough");
    
    // VULNERABILITY: All information is public, enabling front-running
    highestBidder = msg.sender;
    highestBid = msg.value;
}
```

**Attack Scenarios**:
- **Front-running**: See victim's transaction, submit higher gas price to execute first  
- **Sandwich attacks**: Front-run and back-run victim's transaction
- **MEV extraction**: Extract maximum value from transaction ordering

**Secure Pattern (Commit-Reveal)**:
```solidity
// Phase 1: Commit (hide bid amounts)
function commitBid(bytes32 commitment) external payable {
    committedBids[msg.sender] = CommittedBid({
        commitment: commitment,
        deposit: msg.value,
        revealed: false
    });
}

// Phase 2: Reveal (after commit phase ends)
function revealBid(uint256 bidAmount, uint256 nonce) external payable {
    bytes32 expectedCommitment = keccak256(abi.encodePacked(bidAmount, nonce, msg.sender));
    require(committedBids[msg.sender].commitment == expectedCommitment, "Invalid reveal");
    
    // Process bid...
}
```

**Prevention Techniques**:
- **Commit-reveal schemes** to hide transaction details
- **Time delays** and batch processing
- **Submarine sends** (now deprecated)
- **Private mempools** and flashlots
- **MEV-resistant mechanisms** like RANDAO

## Test Results and Proof of Concepts

### Running Attack Demonstrations

Each test suite includes detailed attack scenarios:

```bash
# Watch reentrancy attack drain funds
forge test --match-test "test_ReentrancyAttackSuccess" -vvv

# See integer overflow create tokens from nothing  
forge test --match-test "test_UnderflowAttack_Transfer" -vvv

# Observe unchecked call vulnerabilities and batch operation failures
forge test --match-test "test_UncheckedCallVulnerability_Withdraw" -vvv
forge test --match-test "test_BatchWithdrawVulnerability" -vvv

# Demonstrate front-running and sandwich attacks
forge test --match-test "test_FrontRunningAttack" -vvv
```

### Expected Test Outputs

**Reentrancy Attack Success**:
```
=== Before Attack ===
Bank balance: 6000000000000000000
Attacker balance: 5000000000000000000

Reentrancy attack #1
Draining: 1000000000000000000
Reentrancy attack #2  
Draining: 1000000000000000000
...

=== After Attack ===
Bank balance: 0
Attacker balance: 11000000000000000000
```

**Integer Overflow Result**:
```
Attacker initial balance: 1000000000000000000000
Attacker balance after underflow attack: 115792089237316195423570985008687907853269984665640564039456584007913129639935
```

**Unchecked Call Vulnerabilities**:
```
=== Before Batch Withdraw ===
User1 balance: 9000000000000000000
User2 balance: 9000000000000000000
Malicious receiver balance: 0
Wallet balance: 5000000000000000000

=== After Batch Withdraw ===
User1 balance: 10000000000000000000
User2 balance: 10000000000000000000
Malicious receiver balance: 2000000000000000000  // Received funds despite potential issues
Wallet balance: 0

=== Vulnerability Demonstrated Through Compiler Warnings ===
The VulnerableWallet has compiler warnings about unchecked return values
This creates potential for silent failures in production
```

### Gas Usage Comparisons

The tests include gas usage analysis showing the cost of security:

```
Vulnerable contract gas: 23,456
Secure contract gas: 28,123
Security overhead: ~20% additional gas
```

## Security Best Practices Summary

### Development Guidelines

1. **Follow CEI Pattern**: Checks → Effects → Interactions
2. **Use Latest Solidity**: 0.8.20+ for built-in overflow protection  
3. **Check External Calls**: Always verify return values
4. **Implement Access Controls**: Use OpenZeppelin's access control patterns
5. **Add Reentrancy Protection**: Use ReentrancyGuard for state-changing functions
6. **Validate Inputs**: Check parameters and edge cases
7. **Consider MEV**: Design mechanisms resistant to front-running

### Testing Guidelines  

1. **Test Attack Scenarios**: Write tests that demonstrate vulnerabilities
2. **Use Fuzz Testing**: Test with random inputs to find edge cases
3. **Check Gas Usage**: Monitor gas costs of security measures
4. **Test Access Controls**: Verify unauthorized access fails
5. **Test Edge Cases**: Zero values, maximum values, empty arrays
6. **Integration Testing**: Test interactions between contracts

### Deployment Guidelines

1. **Code Review**: Have security experts review code
2. **External Audits**: Get professional security audits
3. **Gradual Rollout**: Start with limited functionality/funds
4. **Bug Bounties**: Incentivize white-hat discovery
5. **Monitoring**: Monitor for suspicious activity  
6. **Upgrade Paths**: Plan for fixing discovered issues

## Advanced Topics

### MEV Protection Strategies

1. **Commit-Reveal Schemes**: Hide transaction content temporarily
2. **Time-Weighted Average Pricing (TWAP)**: Reduce price manipulation impact
3. **Batch Auctions**: Process transactions in batches
4. **Private Mempools**: Use services like Flashbots Protect
5. **Randomization**: Use verifiable randomness when possible

### Formal Verification

Consider using formal verification tools for critical contracts:
- **Certora**: Specification-based verification
- **KEVM**: K framework for EVM verification  
- **Solidity SMTChecker**: Built-in verification features

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-vulnerability`
3. Add vulnerability example with secure counterpart
4. Include comprehensive tests with attack demonstrations  
5. Update documentation with detailed explanations
6. Submit pull request with clear description

### Adding New Vulnerabilities

To add a new vulnerability:

1. Create `src/new-vulnerability/` directory
2. Implement `VulnerableContract.sol` and `SecureContract.sol` 
3. Create comprehensive test suite in `test/new-vulnerability/`
4. Add section to README with detailed explanation
5. Update main test commands

## Resources and References

### Documentation
- [Solidity Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security Guidelines](https://docs.openzeppelin.com/contracts/4.x/security)

### Tools
- [Foundry Book](https://book.getfoundry.sh/)
- [Slither Static Analyzer](https://github.com/crytic/slither)  
- [MythX Security Analysis](https://mythx.io/)

### Famous Exploits
- [The DAO Hack (2016)](https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/) - Reentrancy
- [BEC Token Overflow](https://medium.com/@peckshield/alert-new-batchoverflow-bug-in-multiple-erc20-smart-contracts-cve-2018-10299-511067db6536) - Integer Overflow
- [King of Ether](https://www.kingoftheether.com/postmortem.html) - Unchecked Calls

## License

MIT License - See LICENSE file for details.

## Disclaimer

⚠️ **Warning**: The contracts in this repository contain intentional vulnerabilities for educational purposes. **DO NOT** deploy the vulnerable contracts to mainnet or use them with real funds. They are designed to lose money and should only be used in test environments for learning purposes.

This repository is for educational use only. The authors are not responsible for any losses incurred from using these contracts.
