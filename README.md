# LKM network capture
A Linux kernel module that captures network packets.

## Compile
### Prerequisite
In order to compile this module, you must have linux headers installed.

A simple method to install linux headers on Ubuntu is using following commands.

```bash
apt-get install linux-headers-$(uname -r)
```

Verify your installation by checking the following directory.

```bash
ls /usr/src/linux-headers-`uname -r`
```

You must also have `gcc` and `make` installed. Install by following commands on Ubuntu.

```bash
apt-get install build-essential
```

### Compile
Compile the module along with the user space program is simple.

```
cd lkm_network_capture
make
```

If no error, a linux kernel module `net.ko` and a user sapce program `client` will produce.

## Usage
### Kernel space
Using following command to load the module

```bash
insmod net.ko
```

Change the parameters only if you are fimilar.

``` bash
insmod net.ko interval=10      # change the time interval to 10ms (default: 1000ms)
insmod net.ko max_size=20000   # change the max packet number in the buffer (default: 10000)
```

### User space
You must have `root` premission to execute user space program.

``` bash
sudo ./client                   # default: output to the console
sudo ./client -f packets.log    # output to the file
sudo ./client -w                # output to the console
sudo ./client -m 20000          # change the max packet number in the buffer (must be consistent with lkm)
```

## Output format
Each record is formatted as follows

```bash
[type]/[protocol] [source address]:[source port] -> [dest address]:[dest port]
```

- type: `ipv4` or `ipv6`
- protocol: IP protocol numbers (see [List of IP protocol numbers](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers))
- address: IP address for source and destination
- port: port for source and destination (only for TCP or UDP protocol)

## Environment
Tested on the following kernel version.
```
Ubuntu 18.04 LTS (linux-headers-4.18.0-25-generic)
Ubuntu 16.04 LTS (linux-headers-4.4.0-142-generic)
```
