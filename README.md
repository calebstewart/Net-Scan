 # Net-Scan - Powershell ping and TCP/UDP port scan implementation

This script will perform a ping and TCP/UDP port scan on the given subnet (IP and subnet mask). 

## Usage

```
PS C:\>.\Net-Scan.ps1 -ip 192.168.13.1 -mask 255.255.255.0 -tcp 88,443,1434 -udp 53
```

# Result

The result is an array of Host objects in Powershell. These objects have the following structure:

- \[string\]host: the host IP address
- \[PSCustomObject\[\]\]ports: an array of open ports
  - \[int\]port: the port number
  - \[string\]type: either `tcp` or `udp`
  - \[string\]state: either `open` or `open|filtered`
- \[boolean\]up: whether the host is up

# Port States

There are two different port states returned by this script. The first is `open`. An `open` TCP port indicates a successfull  TCP 3-way handshake. An `open` UDP port indicates a response was returned from a UDP port. An `open|filtered` UDP port is a port which did not actively reject the UDP packet, but the response timed out. This could indicate the port is open, or that there is a filtering device between you and the target or the target is simply ignoring your requests. See [nmap manual](https://nmap.org/book/man-port-scanning-techniques.html).
