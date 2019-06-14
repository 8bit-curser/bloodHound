# Blood Hound

## Description
Python3 tool to simulate the basic functions of a tool such as `nmap` in network scanning.

- [x] Find active nodes on a network (If my node is 192.168.0.9 looks for nodes from 192.168.0.0 up to 192.168.0.255)
- [x] Find active UDP, TCP ports on a certain host that can be IPV4 or IPV6
- [x] Perform fast port scans (Goes through common ports)
- [x] Perform specific scans (Both TPC and UPD, either TPC or UDP, BOTH IPV6 and IPV4 or either one of those)

* I do not use the ping bash function, we use a pure python implementation that interacts with raw sockets.
* The networkscanner module must be run as **sudo** as following `sudo python3 networkscanner --f` (for a full scan) or `--r 100-125` (for a ranged scan)
* The portscanner can be run without those privileges as `python3 portscanner --c -pt ALL` (common scann that looks for TCP and UDP)


## Things that will be added

- [ ] Rewrite everything in python37 style.
- [ ] Thread support to deliver a faster scan
- [ ] Extend support for other types of ports at the portscanner.
- [ ] Tests for both portscanner and networkscanner.
- [ ] Definitely a more robust logic on the networkscanner (currently works only on OSX).
- [ ] Provide linux support for the networkscanner.
- [ ] Provide Windows support for network and port scanners
- [ ] API interface to have a more visual interaction.
- [ ] PDF reports for the results.
- [ ] Provide a kind of library that could be used using pip to cover common needs. 
