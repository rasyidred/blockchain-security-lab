-include .env

.PHONY: all test clean deploy fund help install snapshot format anvil scopefile

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

LATEST_VERSION=PureWalletV5

all: remove install build build-circom-zkp

# Clean the repo
clean  :; forge clean

# Remove modules
remove :; rm --force .git/index.lock && rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules && git add . && git commit -m "modules" 

# install dependencies, for the latest compiler and circom-zkp submodule
install:
	forge install foundry-rs/forge-std \
		&& forge i OpenZeppelin/openzeppelin-contracts

# Obtain ABI in json
abi :
	forge inspect src/$(LATEST_VERSION).sol:$(LATEST_VERSION) abi > $(LATEST_VERSION).json 
	jq '.abi' out/$(LATEST_VERSION).sol/$(LATEST_VERSION).json  > abi$(LATEST_VERSION).json
	rm $(LATEST_VERSION).json 
	@echo "ABI for $(LATEST_VERSION) contract generated in abi$(LATEST_VERSION).json"

# Update Dependencies
update:; forge update

# build:; forge build

build:; forge build --ignored-error-codes 3860 --ignored-error-codes 2072 --via-ir

test :; forge test --fork-url $(RPC_ETH) --fork-block-number 22865007 --via-ir --ffi --ignored-error-codes 3860

snapshot :; forge snapshot

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

# slither is only in venv, hance make sure to run `source .venv/bin/activate`
slither :; slither ./src/PureWalletV5.sol --config-file slither.config.json --checklist > docs/slither-report.md

scope :; tree ./src/ | sed 's/└/#/g; s/──/--/g; s/├/#/g; s/│ /|/g; s/│/|/g'

scopefile :; @tree ./src/ | sed 's/└/#/g' | awk -F '── ' '!/\.sol$$/ { path[int((length($$0) - length($$2))/2)] = $$2; next } { p = "src"; for(i=2; i<=int((length($$0) - length($$2))/2); i++) if (path[i] != "") p = p "/" path[i]; print p "/" $$2; }' > scope.txt

aderyn :; aderyn . -o ./docs/aderyn-report.md -x test,script,interfaces,token,TokenManager

coverage :; forge coverage --rpc-url $(RPC_ETH) --report lcov && genhtml lcov.info -o report --branch-coverage --via-ir
