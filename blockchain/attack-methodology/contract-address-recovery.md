# Contract Address Recovery

### Create a Contract for Recovery Address <a href="#create-a-contract-for-recovery-address" id="create-a-contract-for-recovery-address"></a>

This contract can compute the contract address which has been lost.

```shellscript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ContractRecovery {

    constructor(address _creatorAddress) {
        address lostAddress = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), address(_creatorAddress), bytes1(0x01))))));
        // some code here ...
    }
}
```

Another way is to use [Etherscan](https://etherscan.io/) transaction history.

### References: <a href="#references" id="references"></a>

* [StackExchange](https://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed)
* [Dixitaditya](https://blog.dixitaditya.com/ethernaut-level-17-recovery)

