---
description: 'Filename in Linux:'
---

# - Dashed files

A dashed filename in Linux is a file or directory whose name starts with a dash (`-`) or double dash (`–`). Such filenames often break commands like `rm`, `cat`, and `mv` because Linux treats them as command options.

This guide shows how to create, open, rename, find, and delete dashed filenames safely using simple command-line examples.

### Common Operations on Dashed Filenames (With Examples)

{% hint style="info" %}
If a filename starts with `-`, always prefix it with `./` or use `--` to stop option parsing.
{% endhint %}

#### Create files and directories starting with dash

```
# Create a file starting with dash
touch -- -file

# Create a directory starting with dash
mkdir -- -dir
```

#### Write to a dashed filename

Redirection works because `>` binds to the filename directly.

```
# Write content to a dashed file
echo "data" > -file
```

#### Read / view a dashed filename

```
# Preferred: prefix with current directory
cat ./-file

# Alternative: use end-of-options marker
cat -- -file
```

#### Rename dashed filenames (file or directory)

```
# Rename dashed file to a safe name
mv -- -file file

# Rename dashed directory
mv -- -dir dir

# Rename dashed file to another dashed filename
mv ./-old ./-new
```

#### Delete dashed filenames safely

```
# Safe deletion using end-of-options marker
rm -- -file

# Safe deletion using path prefix
rm ./-file

# Delete dashed directory
rm -r -- -dir
```

#### Execute a file starting with dash

```
# Execute a script starting with dash
./-script.sh
```

Executing directly avoids option parsing entirely.

#### Edit dashed filenames in editors

```
# Open in vim
vim -- -file

# Open in nano
nano -- -file
```

#### Find dashed filenames

```
# Files starting with dash
find . -type f -name "-*"

# Directories starting with dash
find . -type d -name "-*"

# Any file containing dash
find . -name "*-*"
```

### What is single dash (`-`) and double dash (`–`) in Posix?

As per [Posix Guidelines](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html#tag_12_02)

* All options should be preceded by the `-` delimiter character.
* So all the options which is provided to any tool such as the most used option `--help` or `-h` should start with single dash (`-`)
* For utilities that use operands to represent files to be opened for either reading or writing, the `-` operand should be used to mean only **standard input** (or **standard output** when it is clear from context that an output file is being specified) or a file named `-`
* The first `--` argument that is not an option-argument should be accepted as a delimiter indicating the **end of options**. Any following arguments should be treated as **operands**, even if they begin with the `-` character.

### How to create dashed filename and directories?

In the Linux environment, creating files and directories with dashes, especially at the beginning or end of the name, is possible, but it comes with its own set of peculiarities. Let’s delve into the methodologies and potential pitfalls of this practice.

**Using `touch`:**

The `touch` command is frequently used to create empty files in Linux. To create a file with a dash at the beginning or end, you’d typically enclose the name in quotes:

```
touch -- "-filename" # starts with a dash
touch "filename-" # ends with a dash
```

When creating a filename starting with dash then you have to pass `--` argument which indicates the end of command options. After `--`, all arguments are treated as filenames and not options.

If you don’t pass `–` then you may get below error:

```
touch: invalid option -- 'i'
Try 'touch --help' for more information.
```

**Using Redirection:**

Redirection is another method to create or write to files. For filenames with dashes, the approach is similar:

```
echo "content" > "-filename"
echo "content" > "filename-"
```

**Creating Directories with Dashes in Linux**

**Using `mkdir` to Create Directories**: The `mkdir` command is used to create directories in Linux. Just like with `touch`, if you want to create a directory with a dash at the beginning or the end, special care is needed. To create a directory named `-dirName`:

```
mkdir -- -dirName
```

To create a directory named `dirName-`:

```
mkdir dirName-
```

### How to open and read dashed filename?

The usual syntax from `cat` **will not work** as `cat` would consider (`-`) as an `STDIN` and wait for user INPUT on the screen.

```
# cat -
```

You can tweak the `cat` syntax to check the content of (`-`)

```
# cat < -
server1.example.com
```

The **proper way to view content** of dashed filename would be again to prefix the path of the file

```
# cat ./-
Mon May 18 15:02:44 IST 2020
server1.example.com
```

You can use any supported command such as `more`, `less`, `tail`, `head` to view the content using the path with filename

```
# more ./-
Mon May 18 15:02:44 IST 2020
server1.example.com
```

We can also use double dash (`–`) combined with [cat or other similar commands](https://www.golinuxcloud.com/cat-command-in-linux/) to view a dashed filename

```
# echo "some content" > -file
# echo "some more content" > -file2
```

View the content of the file using (`--`)

```
# cat -- -file
some content

# cat -- -file2
some more content
```

### How to Rename Dashed Filenames?

Working with dashed filenames in Linux, especially those beginning with a dash, requires particular attention to ensure the commands are executed as intended. Here’s a guide on how to rename such files using the `mv` command.

**Standard Rename**: For filenames that have dashes but don’t begin with them, you use the `mv` command as you would with any other file:

```
mv filename- newfilename
```

**Renaming Files Beginning with a Dash**: If the filename starts with a dash, it can be confused as an option for the `mv` command. In this case, you’ll have to use a specific format to ensure it’s interpreted as a filename:

```
mv -- -filename newfilename
```

The `--` indicates to the `mv` command that there are no more options after it, and thus `-filename` is treated as a file and not an option.

Renaming a filename that starts with a dash to another filename that also starts with a dash can be tricky because command-line utilities might interpret the dashed name as an option. However, you can use the `mv` command with the `./` prefix to specify that you’re referring to a file in the current directory.

For example, let’s say you have a file named `-oldfile.txt` and you want to rename it to `-newfile.txt`. Here’s how you can do it:

```
mv ./-oldfile.txt ./-newfile.txt
```

The `./` prefix indicates that the filename follows, ensuring that the file named `-oldfile.txt` in the current directory is interpreted as a filename and not as an option to the `mv` command.

### How to Delete Files with Dashed Filenames?

Managing files with dashes, particularly those that commence with a dash, demands special care in Linux to evade unintended actions. The `rm` command, commonly used to [delete files](https://www.golinuxcloud.com/python-delete-file-examples/), can exhibit peculiar behavior with dashed filenames. Here’s a guide to safely remove such files.

**The `rm` Command and its Peculiar Behavior with Dashed Filenames**

**Standard Deletion**: If a file has dashes but doesn’t start with one, you use the `rm` command in the usual manner:

```
rm filename-
```

**Deleting Files Beginning with a Dash**: Files starting with a dash can be perceived as options by the `rm` command. Hence, the regular deletion method **may not work** and can even result in an error. For example:

```
rm -filename
```

This could be mistaken by the `rm` command as trying to delete using the `-f` and `-i` options, followed by a file named `lename`, which is not what’s intended.

**Safely Removing Files with Dashes without Unwanted Consequences**

**Using the `--` Convention**: The `--` argument indicates that there are no more options after it. It ensures that what follows is treated as a filename, not an option.

```
rm -- -filename
```

**Using the `./` Prefix**: Another method to safely remove files beginning with a dash is to prefix them with `./`, which signifies the current directory:

```
rm ./-filename
```

### How to Find Files with Dashed Names?

Finding files with specific patterns, such as dashed names, is a common requirement in Linux. The operating system provides a variety of tools for this purpose, most notably `find` and `grep`. Let’s look into the methodologies and techniques of locating such files.

**Utilizing the `find` Command**

**Finding Files with Dashes Anywhere in the Name**:

```
find /path/to/search -type f -name "*-*"
```

This command searches the directory `/path/to/search` for all files (`-type f`) with dashes in their names.

**Finding Files Starting with a Dash**:

```
find /path/to/search -type f -name "-*"
```

Here, the pattern `-name "-*"` matches files that start with a dash.

**Finding Files Ending with a Dash**:

```
find /path/to/search -type f -name "*-"
```

This command finds files ending with a dash.

**Using `grep` in Conjunction with Other Commands**

While `find` is powerful for file searching, sometimes we might need the help of other commands. `grep` is a text search utility, and it can be combined with commands like `ls` for pattern searching.

**Listing Files with Dashes and Filtering with `grep`**:

```
ls /path/to/search | grep '^-'
```

This command lists all entities in `/path/to/search` and then filters out only those that start with a dash.

**Techniques to Narrow Down Searches for Dashed Filenames**

**Combining Search Criteria**: You can combine different search patterns with `find` to narrow down your results. For example, to find text files starting with a dash:

```
find /path/to/search -type f -name "-*.txt"
```

**Limiting Depth of Search**: If you only want to search the top directory and not delve into subdirectories, you can limit the depth:

```
find /path/to/search -maxdepth 1 -type f -name "*-*"
```

**Using `grep` with Regular Expressions**: `grep` can use extended regular expressions for more complex pattern matching. For example, to find files that have a dash followed by numbers:

```
ls /path/to/search | grep '^[^-]*-[0-9]\+'
```

**Modified Time**: To find dashed filenames modified in the last 7 days:

```
find /path/to/search -type f -name "*-*" -mtime -7
```

### Frequently Asked Questions

<details>

<summary>Why do some filenames start with a dash?</summary>

Filenames starting with a dash can be created either mistakenly (usually a result of command misinterpretation) or intentionally for specific purposes like making the file less noticeable or harder to accidentally modify. However, it’s generally not a standard or recommended practice as it can lead to command ambiguities.

</details>

<details>

<summary>How can I prevent accidental creation of files starting with a dash?</summary>

Always double-check your commands before execution. When redirecting outputs to a file, ensure there’s no space between the redirection operator and the filename. If scripting, include checks to validate filenames.

</details>

<details>

<summary>Why does the command <code>rm -filename</code> not work?</summary>

Commands interpret text after a dash as an option. So, `rm -filename` might be interpreted as trying to delete using the `-f` option followed by a file named `ilename`. Use `rm -- -filename` or `rm ./-filename` to safely delete such files.

</details>

<details>

<summary>Can I create directories starting with a dash?</summary>

Yes, the same principles that apply to dashed filenames also apply to directory names. You can create them using `mkdir -- -dirname` or `mkdir ./-dirname`.

</details>

<details>

<summary>Is there a way to list only files that have dashes in their names?</summary>

Yes, you can use the `find` command (`find /path -type f -name "*-*"`) or a combination of `ls` and `grep` (`ls /path | grep "-"`).

</details>

<details>

<summary>How do I open a file with a dash at the beginning in a text editor like <code>nano</code> or <code>vim</code>?</summary>

Use the `--` convention to prevent the editor from interpreting the filename as an option: `nano -- -filename` or `vim -- -filename`.

</details>

### Summary

Dashed filenames in Linux, while valid, can pose unique challenges, especially when the filename begins with a dash. These filenames can sometimes be interpreted as command options, leading to unexpected behavior. To navigate these challenges, it’s crucial to adopt certain best practices, such as being cautious with naming conventions, understanding command conflicts, and encapsulating filenames in quotes.

### Additional Resources

**POSIX Utility Conventions**

[Official POSIX specification](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html) that explains command-line option parsing, the special meaning of the `-` operand, and the use of `--` as the end-of-options delimiter.

**GNU Core Utilities Manual**

[Official documentation for core Linux utilities](https://www.gnu.org/software/coreutils/manual/coreutils.html) such as `touch`, `rm`, `mv`, and `find`, all of which are commonly affected by filenames starting with a dash.

**Linux Man Pages**

Built-in manual pages that describe how individual commands handle files and options:

* `touch`: Create a file. [Man Page](https://man7.org/linux/man-pages/man1/touch.1.html)
* `rm`: Remove files or directories. [Man Page](https://man7.org/linux/man-pages/man1/rm.1.html)
* `mv`: Move or rename files. [Man Page](https://man7.org/linux/man-pages/man1/mv.1.html)
* `find`: Search for files in a directory hierarchy. [Man Page](https://man7.org/linux/man-pages/man1/find.1.html)

**GNU Bash Manual**

Explains how the [Bash shell](https://www.gnu.org/software/bash/manual/bash.html) parses command-line arguments and filenames before passing them to commands, which is essential for understanding dashed filename behavior.

**Filesystem Hierarchy Standard (FHS)**

Reference documentation describing [Linux filesystem structure and conventions](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/index.html), useful for understanding where and why certain files may exist.

**Unix StackExchange – Filenames starting with dash**

A canonical community discussion covering real-world pitfalls and [safe handling patterns for filenames that begin with a dash](https://unix.stackexchange.com/questions/1519/how-do-i-delete-a-file-whose-name-begins-with-a-hyphen).
