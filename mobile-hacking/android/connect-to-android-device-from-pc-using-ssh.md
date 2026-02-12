# Connect to Android Device from PC using SSH

Use Termux for connecting to Android device from your laptop or desktop.

### 1. Preparation <a href="#id-1-preparation" id="id-1-preparation"></a>

#### 1. Create SSH Private/Public Key Pair on Linux Machine <a href="#id-1-create-ssh-privatepublic-key-pair-on-linux-machine" id="id-1-create-ssh-privatepublic-key-pair-on-linux-machine"></a>

In our machine, we need to generate SSH key pair for connecting to SSH server of Android device.\
After running the following command, there's no problem with no passphrase if it's for testing purpose.

```shellscript
ssh-keygen -t ed25519 -f id_ed25519_android
```

After that, store the generated files (`id_25519_android`, `id_25519_android.pub`) into `~/.ssh` folder.

```shellscript
# If `.ssh` directory does not exist, create a new one.
mkdir -p ~/.ssh
mv id_ed25519_android* ~/.ssh/
```

#### 2. Send SSH Public Key to Android Device <a href="#id-2-send-ssh-public-key-to-android-device" id="id-2-send-ssh-public-key-to-android-device"></a>

We need to send our `id_25519_android.pub` to an **Android** device. There are various ways to do that such as bellow:

* Using a **USB** cable.
* Using **Bluetooth**.
* Using email such as **Gmail**.

#### 3. Install Termux in Android <a href="#id-3-install-termux-in-android" id="id-3-install-termux-in-android"></a>

Install it from [F-Droid](https://f-droid.org/en/packages/com.termux/). According to the official, installing from Google Play is deprecated.

#### 4. Update/Upgrade Packages in Termux <a href="#id-4-updateupgrade-packages-in-termux" id="id-4-updateupgrade-packages-in-termux"></a>

After installing Termux, open it and execute the following commands.

```shellscript
pkg update
pkg upgrade
apt update
apt upgrade
```

If you got the error “repository is under maintenance or down (wrong sources.list URL?)”, change the mirrors using `termux-change-repo` or modify `sources.list` directly as follows.

```shellscript
echo "deb https://grimler.se/termux-packages-24 stable main" > $PREFIX/etc/apt/sources.list
echo "deb https://grimler.se/termux-packages-24 stable main" > $PREFIX/etc/apt/sources.list.d/game.list
echo "deb https://grimler.se/termux-packages-24 stable main" > $PREFIX/etc/apt/sources.list.d/science.list
```

Please see [the termux package issue](https://github.com/termux/termux-packages/issues/6726) for details.

#### 5. Install Packages in Termux <a href="#id-5-install-packages-in-termux" id="id-5-install-packages-in-termux"></a>

```shellscript
pkg install openssh
pkg install iproute2
pkg install nmap
```

* `openssh`: Required to start SSH server.
* `iproute2`: Required to check the SSH port number.
* `nmap`: Required to confirm the SSH server is running.

After installing `openssh`, our SSH host configurations and keys are stored under `/data/data/com.termux/files/usr/etc/ssh/`.

#### 6. Link Android Storage to Termux <a href="#id-6-link-android-storage-to-termux" id="id-6-link-android-storage-to-termux"></a>

By default, Termux does not have access to Android storage, so we need to create a symbolic link to it wiht `termux-setup-storage` command.

```
termux-setup-storage
```

After that `storage` directory is generated under the Termus home directory (`/data/data/com.termux/files/home`) which is a symbolic link to `/storage` directory.\
Our `id_ed25519_android.pub` file which was transferred from our machine may exist in this directory.

```shellscript
cd /data/data/com.termux/files/home/storage
ls
# downloads movies music pictures shared

cd downloads
ls
# id_ed25519_android.pub

# Check physical directory
pwd -P
# /storage/emulated/0/Download
```

### 2. Start SSH Server in Android <a href="#id-2-start-ssh-server-in-android" id="id-2-start-ssh-server-in-android"></a>

#### 1. Add SSH Public Key to authorized\_keys <a href="#id-1-add-ssh-public-key-to-authorized_keys" id="id-1-add-ssh-public-key-to-authorized_keys"></a>

```shellscript
cat /data/data/com.termux/files/home/storage/downloads/id_ed25519.pub >> ~/.ssh/authorized_keys

# Change permission
chmod 600 ~/.ssh/authorized_keys
```

#### 2. Start SSH Daemon <a href="#id-2-start-ssh-daemon" id="id-2-start-ssh-daemon"></a>

In Android device, run `sshd` command to start SSH server.

```shellscript
sshd
```

#### 3. Check SSH Port Number <a href="#id-3-check-ssh-port-number" id="id-3-check-ssh-port-number"></a>

In Android device, check the SSH port number using `nmap` command. This port number will be used for connecting the SSH server from our machine.

```shellscript
nmap localhost
```

### 3. Connect to Android SSH Server From PC <a href="#id-3-connect-to-android-ssh-server-from-pc" id="id-3-connect-to-android-ssh-server-from-pc"></a>

#### 1, Get IP Address of Android Device <a href="#id-1-get-ip-address-of-android-device" id="id-1-get-ip-address-of-android-device"></a>

In Android device, run the following command to retrieve the IP addressd on the network.\
Please note that both our machine (laptop or desktop) and Android device must connect to the same WiFi network.

```
ip -4 addr
```

We should see `wlan0` interface and the IP address such as `192.168.11.123` in the `inet` section. Take a note this address.

#### 2. Connect to SSH Server from Our Machine <a href="#id-2-connect-to-ssh-server-from-our-machine" id="id-2-connect-to-ssh-server-from-our-machine"></a>

In our machine, run the following command.\
Assume that the Android’s IP address is `192.168.11.123` and the SSH port number is `8022`.\
If successful, we can take control of our Android device from our machine.

```shellscript
ssh -i ~/.ssh/id_ed25519_android 192.168.11.123 -p 8022

$ whoami
u0_a123
```

### Optional. Stop SSH Server on Android <a href="#optional-stop-ssh-server-on-android" id="optional-stop-ssh-server-on-android"></a>

After finish playing with Android, it’s better to stop the SSH server.

```shellscript
# Check PID of `sshd`
ps -e | grep sshd
# Kill the process
kill -9 <PID>
```

To check the SSH daemon stops, use `ps` or `nmap`.

```shellscript
ps -e
nmap localhost
```
