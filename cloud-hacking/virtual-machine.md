# Virtual Machine

## VM (Virtual Machine) Escape <a href="#vm-virtual-machine-escape" id="vm-virtual-machine-escape"></a>

### Shared Folder <a href="#shared-folder" id="shared-folder"></a>

If the VM admin sets a folder containing sensitive files as Shared Folder, we can get sensitive information by getting into the folder.

#### VirtualBox <a href="#virtualbox" id="virtualbox"></a>

```shellscript
# Linux
cd /media/sf_<folder-name>

# Windows
cd \\VBOXSVR\\<folder-name>
```

#### VMWare <a href="#vmware" id="vmware"></a>

```shellscript
# Linux
cd /mnt/vmhgs/<folder-name>

# Windows
cd \\vmware-host\Shared Folder\<folder-name>
```
