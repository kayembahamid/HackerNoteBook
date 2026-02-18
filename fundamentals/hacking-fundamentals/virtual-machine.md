# Virtual Machine

### <mark style="color:blue;">Overview</mark>

* Virtual machines (VMs) allow a business to run an operating system that behaves like a completely separate computer in an app window on a desktop. VMs may be deployed to accommodate different levels of processing power needs, to run software that requires a different operating system, or to test applications in a safe, sandboxed environment.
* Virtual machines have historically been used for server virtualization, which enables IT, teams, to consolidate their computing resources and improve efficiency. Additionally, virtual machines can perform specific tasks considered too risky to carry out in a host environment, such as accessing virus-infected data or testing operating systems. Since the virtual machine is separated from the rest of the system, the software inside the virtual machine cannot tamper with the host computer.

### <mark style="color:blue;">How do virtual machines work?</mark>

The virtual machine runs as a process in an application window, similar to any other application, on the operating system of the physical machine. Key files that make up a virtual machine include a log file, an NVRAM setting file, a virtual disk file, and a configuration file.

### <mark style="color:blue;">Advantages of virtual machines</mark>

Virtual machines are easy to manage and maintain, and they offer several advantages over physical machines:

* VMs can run multiple operating system environments on a single physical computer, saving physical space, time, and management costs.
* Virtual machines support legacy applications, reducing the cost of migrating to a new operating system. For example, a Linux virtual machine running a distribution of Linux as the guest operating system can exist on a host server that is running a non-Linux operating system, such as Windows.
* VMs can also provide integrated disaster recovery and application provisioning options.

### <mark style="color:blue;">Disadvantages of virtual machines</mark>

While virtual machines have several advantages over physical machines, there are also some potential disadvantages:

* Running multiple virtual machines on one physical machine can result in unstable performance if infrastructure requirements are not met.
* Virtual machines are less efficient and run slower than a full physical computer. Most enterprises use a combination of physical and virtual infrastructure to balance the corresponding advantages and disadvantages.

{% embed url="https://www.youtube.com/watch?v=yHT4kq36PE4&t=3s&pp=ygUddm0gIHNldHVwIGRhdmlkIGJhbWJvbCBvbiBtYWPSBwkJhwoBhyohjO8%3D" %}

### <mark style="color:blue;">Setting up a virtual machine</mark>

{% embed url="https://www.youtube.com/watch?v=MPkni85O9JA&pp=ygUidm0gIHNldHVwIGRhdmlkIGJhbWJvbCB2aXJ0YXVsIGJveA%3D%3D" %}

#### <mark style="color:blue;">Using Oracle VM</mark>

Set up a virtual machine using Oracle VM:

1. Download and install Oracle VM VirtualBox.
2. Create a new virtual machine.
3. Select the kali Linux as an OS.
4. Allocate memory and storage space for the virtual machine.
5. Create a virtual hard disk.
6. Install the operating system on the virtual machine.

Here are the detailed steps for each:

1. Download and install Oracle VM VirtualBox from the Oracle website
2. To create a new virtual machine, open Oracle VM VirtualBox and click the "New" button.
3. In the "Name" field, enter a name for your virtual machine.
4. In the "Operating System" drop-down list, select kali Linux as an OS.
5. In the "Version" drop-down list, select the version of the operating system you want to install.
6. In the "Memory" field, enter the amount of memory you want to allocate to the virtual machine.
7. In the "Hard Disk" section, click the "Create a virtual hard disk now" option.
8. In the "File Location" field, enter the location where you want to store the virtual hard disk file.
9. In the "File Size" field, enter the size of the virtual hard disk file.
10. Click the "Create" button.

Oracle VM VirtualBox will create a new virtual machine and start it up. You will then be prompted to install the operating system on the virtual machine.

Once the operating system is installed, you can start using your virtual machine. You can access the virtual machine from the Oracle VM VirtualBox Manager.

Here are some additional tips for setting up a virtual machine using Oracle VM:

* If you are using a Windows computer, you may need to enable virtualization in your BIOS.
* You can create multiple virtual machines on the same computer.
* You can share files and folders between your host computer and your virtual machines.
* You can use a virtual machine to run operating systems that are not compatible with your host computer.

{% embed url="https://www.youtube.com/watch?v=wX75Z-4MEoM&t=1176s&pp=ygUWdm0gIHNldHVwIGRhdmlkIGJhbWJvbA%3D%3D" %}

#### <mark style="color:blue;">Using VMware</mark>

{% embed url="https://www.youtube.com/watch?v=XzD8JIAOk2I&pp=ygUWdm0gIHNldHVwIGRhdmlkIGJhbWJvbA%3D%3D" %}

set up a virtual machine using VMware to run Kali Linux:

1. Install VMware Workstation Player on your computer. You can download it from the VMware website.
2. Download the Kali Linux ISO image from the Kali Linux website.
3. Create a new virtual machine in VMware Workstation Player.
4. Select the Kali Linux ISO image as the installation media.
5. Configure the virtual machine settings. You should allocate at least 4 GB of RAM and 20 GB of disk space to the virtual machine.
6. Start the installation process.
7. Follow the on-screen instructions to install Kali Linux.

Once Kali Linux is installed, you can connect to it using the VMware Workstation Player console. You can also connect to it using a remote desktop connection.

Here are some additional tips for setting up a virtual machine using VMware to run Kali Linux:

* Make sure that your computer meets the minimum system requirements for VMware Workstation Player.
* You can use a USB drive to transfer files between your host computer and the virtual machine.
* You can use a shared folder to access files on your host computer from the virtual machine.
* You can use a virtual network adapter to connect the virtual machine to the internet.
