raspberrypi = ["raspberrypi", "rpi", "rpi4", "rpi3", "bcm43455c0", "bcm43455", "Raspberry Pi B3+/B4"]
nexus5 = ["nexus5", "bcm4339", "Nexus 5"]
nexus6p = ["nexus6p", "bcm4358", "Nexus 6P"]
rtac86u = ["rtac86u", "bcm4366c0", "Asus RT-AC86U"]


def decoder(device):
    if device in raspberrypi or nexus5:
        from nexcsi import interleaved
        return interleaved
    elif device in nexus6p:
        from nexcsi import floating
        floating.unpack = lambda csi, device, fftshift: floating.unpack(csi, nexus6p[0], fftshift)
        return floating
    elif device in rtac86u:
        from nexcsi import floating
        floating.unpack = lambda csi, device, fftshift: floating.unpack(csi, rtac86u[0], fftshift)
        return floating
    else:
        raise ValueError(
            f"Device '{device}' seems to be an unsupported format. " +
            "Please create a new issue at " +
            "https://github.com/nexmonster/nexcsi/issues " +
            "if you think this is an bug."
        )