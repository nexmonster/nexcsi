# Nexcsi

Nexcsi is a fast and simple CSI decoder for Nexmon_CSI files written in Python.

``` bash
pip install nexcsi
```

# Usage

``` python
from nexcsi import decoder

device = "raspberrypi" # nexus5, nexus6p, rtac86u

samples = decoder(device).read_pcap('pcap/output10k.pcap')

print(samples['rssi']) # [-75 -77 -77 ... -77 -76 -76]
print(samples['fctl']) # [128 148 148 ... 148 148 148]
print(samples['csi'])  # [[ 19489  0  -19200  -96 -42 ...

# samples is a Numpy Structured Array
print(samples.dtype)

# [
#     ('ts_sec', '<u4'), ('ts_usec', '<u4'), ('saddr', '>u4'), 
#     ('daddr', '>u4'), ('sport', '>u2'), ('dport', '>u2'),
#     ('magic', '<u2'), ('rssi', 'i1'), ('fctl', 'u1'),
#     ('mac', 'u1', (6,)), ('seq', '<u2'), ('css', '<u2'),
#     ('csp', '<u2'), ('cvr', '<u2'), ('csi', '<i2', (512,))
# ]

# Accessing CSI as type complex64
csi = decoder(device).unpack(samples['csi'])
```

### Null and Pilot subcarriers

CSI values of some subcarriers contain large and arbitrary values.
Removing or zeroing them can make the changes in CSI better visible.

To zero the values of Null and Pilot subcarriers:

``` python
csi = decoder(device).unpack(samples['csi'], zero_nulls=True, zero_pilots=True)
```

Alternatively you can completely delete the columns of those subcarriers.
Although I don't recommend this, because it changes the indexes of other subcarriers.

``` python
import numpy as np

csi = np.delete(csi, csi.dtype.metadata['nulls'], axis=1)
csi = np.delete(csi, csi.dtype.metadata['pilots'], axis=1)
```