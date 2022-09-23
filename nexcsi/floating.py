"""
Interleaved
===========

Fast and efficient methods to extract
Interleaved CSI samples in PCAP files.

~640k 80MHz samples per second.

Suitable for bcm4358 and bcm4366c0 chips.

Requires Numpy.

Usage
-----

from nexcsi import interleaved

samples = floating.read_pcap('path_to_pcap_file')

Bandwidth is inferred from the pcap file, but
can also be explicitly set:

samples = floating.read_pcap('path_to_pcap_file', bandwidth=40)
"""

__all__ = ["read_pcap"]

import os
import numpy as np
from nexcsi._decoder import nexus6p, rtac86u


def __find_bandwidth(incl_len):
    """
    Determines bandwidth
    from length of packets.

    incl_len is the 4 bytes
    indicating the length of the
    packet in packet header
    https://wiki.wireshark.org/Development/LibpcapFileFormat/

    This function is immune to small
    changes in packet lengths.
    """

    pkt_len = int.from_bytes(incl_len, byteorder="little", signed=False)

    # The number of bytes before we
    # have CSI data is 60. By adding
    # 128-60 to frame_len, bandwidth
    # will be calculated correctly even
    # if frame_len changes +/- 128
    # Some packets have zero padding.
    # 128 = 20 * 3.2 * 4
    nbytes_before_csi = 60
    pkt_len += 128 - nbytes_before_csi

    bandwidth = 20 * int(pkt_len // (20 * 3.2 * 4))

    return bandwidth


def __find_nsamples_max(pcap_filesize, nsub):
    """
    Returns an estimate for the maximum possible number
    of samples in the pcap file.

    The size of the pcap file is divided by the size of
    a packet to calculate the number of samples. However,
    some packets have a padding of a few bytes, so the value
    returned is slightly higher than the actual number of
    samples in the pcap file.
    """

    # PCAP global header is 24 bytes
    # PCAP packet header is 12 bytes
    # Ethernet + IP + UDP headers are 46 bytes
    # Nexmon metadata is 18 bytes
    # CSI is nsub*4 bytes long
    #
    # So each packet is 12 + 46 + 18 + nsub*4 bytes long
    nsamples_max = int((pcap_filesize - 24) / (12 + 46 + 18 + (nsub * 4)))

    return nsamples_max


def unpack(csi, device, fftshift=True):
    if device in rtac86u:
        nman = 12
        nexp = 6
    elif device in nexus6p:
        nman = 9
        nexp = 5
    else:
        raise ValueError(
            f"Device '{device}' seems to be an unsupported format. " +
            "Please create a new issue at " +
            "https://github.com/nexmonster/nexcsi/issues " +
            "if you think this is an bug."
        )

    csi_flat = csi.flatten()

    mask_iq = (1 << (nman - 1)) - 1
    mask_ex = (1 << (nexp - 1)) - 1

    mask_sign_i = (1 << (nexp + 2 * nman - 1))
    mask_sign_q = (1 << (nexp + 1 * nman - 1))
    # mask_sign_e = (1 << (nexp + 0 * nman - 1))

    # print(np.binary_repr(mask_sign_i, width=32))
    # print(np.binary_repr(mask_iq << nexp + nman, width=32))
    # print(np.binary_repr(mask_sign_q, width=32))
    # print(np.binary_repr(mask_iq << nexp, width=32))
    # print(np.binary_repr(mask_sign_e, width=32))
    # print(np.binary_repr(mask_ex, width=32))

    value_i = np.bitwise_and(csi_flat, mask_iq << nexp + nman).astype(np.int64)
    value_q = np.bitwise_and(csi_flat, mask_iq << nexp).astype(np.int64)
    value_e = np.bitwise_and(csi_flat, mask_ex).astype(np.int64)

    value_i = np.right_shift(value_i, nexp + nman)
    value_q = np.right_shift(value_q, nexp)

    sign_i = np.bitwise_and(csi_flat, mask_sign_i).astype(np.int64)
    sign_q = np.bitwise_and(csi_flat, mask_sign_q).astype(np.int64)
    # sign_e = np.bitwise_and(csi_flat, mask_sign_e).astype(np.int64)

    value_i[sign_i != 0] *= -1
    value_q[sign_q != 0] *= -1

    value_e += 10
    value_e = np.power(2, value_e)

    value_i *= value_e
    value_q *= value_e

    unpacked = np.stack((value_i, value_q), axis=1).flatten().astype(np.float32).view(np.complex64)

    unpacked = unpacked.reshape(csi.shape)

    if fftshift:
        unpacked = np.fft.fftshift(unpacked, axes=(1,))

    return unpacked


def read_pcap(pcap_filepath, bandwidth=None, nsamples_max=None):
    """
    Reads CSI samples from
    a pcap file. A SampleSet
    object is returned.

    Bandwidth and maximum samples
    are inferred from the pcap file by
    default, but you can also set them explicitly.
    """

    pcap_filesize = os.stat(pcap_filepath).st_size

    with open(pcap_filepath, "rb") as pcapfile:
        fc = pcapfile.read()  # ~2.68 s

    if bandwidth is None:
        bandwidth = __find_bandwidth(
            # 32-36 is where the incl_len
            # bytes for the first frame are
            # located.
            # https://wiki.wireshark.org/Development/LibpcapFileFormat/
            fc[32:36]
        )

    # Number of OFDM sub-carriers
    nsub = int(bandwidth * 3.2)

    if nsamples_max is None:
        nsamples_max = __find_nsamples_max(pcap_filesize, nsub)

    # Numpy dtype for sample: https://numpy.org/doc/stable/reference/arrays.dtypes.html
    dtype_sample = np.dtype(
        [
            ("magic", np.uint16),
            ("rssi", np.int8),
            ("fctl", np.uint8),
            ("mac", np.uint8, 6),
            ("seq", np.uint16),
            ("css", np.uint16),
            ("csp", np.uint16),
            ("cvr", np.uint16),
            ("csi", np.uint32, nsub),
        ]
    )

    # Number of bytes in a sample
    nbytes_sample = dtype_sample.itemsize

    # Pre-allocating memory to contain all samples
    data = bytearray(nsamples_max * nbytes_sample)  # ~ 1.5s

    # This is to track our current position in the bytearray `data`
    data_index = 0

    # Pointer to current location in file.
    # This is faster than using file.tell()
    # =24 to skip pcap global header
    ptr = 24

    nsamples = 0
    while ptr < pcap_filesize:
        # Read frame header
        # Skip over Eth, IP, UDP
        ptr += 8
        frame_len = int.from_bytes(  # ~ 3 s
            fc[ptr : ptr + 4], byteorder="little", signed=False
        )
        ptr += 50

        data[data_index : data_index + nbytes_sample] = fc[
            ptr : ptr + nbytes_sample
        ]  # ~ 5.2 s

        nsamples += 1
        ptr += frame_len - 42
        data_index += nbytes_sample

    samples = np.frombuffer(
        data[:data_index], dtype=dtype_sample, count=nsamples
    )  # ~ 1.8 s

    return samples
