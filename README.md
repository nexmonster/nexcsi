# Nexcsi

Nexcsi is a fast and simple CSI decoder for Nexmon_CSI files written in Python.

``` bash
pip install nexcsi
```

# Usage

``` python

from nexcsi import decoder

samples = decoder('bcm43455c0').read_pcap('csirecording.pcap')

print(samples['rssi']) # [-75 -77 -77 ... -77 -76 -76]
print(samples['fctl']) # [128 148 148 ... 148 148 148]
print(samples['csi'])  # [[ 19489  0  -19200  -96 -42]]

# samples is a Numpy Structured Array
print(samples.dtype)

# [
#     ('magic', '<u2'), ('rssi', 'i1'), ('fctl', 'u1'),
#     ('mac', 'u1', (6,)), ('seq', '<u2'), ('css', '<u2'),
#     ('csp', '<u2'), ('cvr', '<u2'), ('csi', '<i2', (512,))
# ]

# Accessing CSI as type complex64
csi = samples["csi"].astype(np.float32).view(np.complex64)

# fftshift CSI to have null subcarrier at the center
csi = np.fft.fftshift(csi, axes=(1,))
```