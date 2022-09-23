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
#     ('magic', '<u2'), ('rssi', 'i1'), ('fctl', 'u1'),
#     ('mac', 'u1', (6,)), ('seq', '<u2'), ('css', '<u2'),
#     ('csp', '<u2'), ('cvr', '<u2'), ('csi', '<i2', (512,))
# ]

# Accessing CSI as type complex64
csi = decoder(device).unpack(samples['csi'])
```