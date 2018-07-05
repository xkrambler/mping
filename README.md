# mping
**mping** is a Massive PING tool for Linux. It throws ICMP PING packets for all hosts at same time and wait for the replies asyncrounosly. This allows fast scanning hosts in big networks (1000+ devices) with the limit of the network bandwidth.

## Building
As easy as run the Makefile:
```
make
```
As we are using RAW packets, **you must run it as superuser**. Also, compiling as superuser sets owner to root:root and the sticky bit. Example:
```
sudo ./mping inertinc.com google.es 8.8.8.8
```
Required libraries: ```lpthread```

## Installing and Uninstalling
Simply run ```make install``` to install it or ```make uninstall``` to uninstall. By default, it will be installed on ```/usr/bin/mping```.

## Syntax
```
Usage: ./mping [options] [target]
   -t timeout   Timeout in miliseconds
   -r retries   Retry down hosts extra times
   -n           Do not show hostnames, only IP addresses
   -v           Show version
   -h           Show this help
```

## More examples
If no targets are specified, it will read the standard input, so you can pipe the list of hosts...
```
echo 8.8.8.8 | ./mping
```
...or use a file (each host in a new line)...
```
./mping < hostlist.txt
```
