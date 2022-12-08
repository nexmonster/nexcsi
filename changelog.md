0.5.0
=====

Date: Dec 08 2022

`unpack` can now set the CSI of Null and 
Pilot subcarriers to 0.

Some metadata is available in dtype.metadata
for samples and csi, but I won't recommend relying
on it too much. 

0.4.0
=====

Date: Nov 15 2022

Following additional fields are now read
from PCAPs for floating and interleaved:
- Timestamp Seconds
- Timestamp Microseconds
- Source IP Address
- Destination IP Address
- Source UDP Port
- Destination UDP Port

