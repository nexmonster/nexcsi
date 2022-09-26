from functools import partial

raspberrypi = ["raspberrypi", "rpi", "rpi4", "rpi3", "bcm43455c0", "bcm43455", "Raspberry Pi B3+/B4"]
nexus5 = ["nexus5", "bcm4339", "Nexus 5"]
nexus6p = ["nexus6p", "bcm4358", "Nexus 6P"]
rtac86u = ["rtac86u", "bcm4366c0", "Asus RT-AC86U"]


def decoder(device):
    if device in raspberrypi + nexus5:
        from nexcsi import interleaved
        interleaved.unpack = partial(interleaved.unpack, device=device)
        return interleaved
    elif device in nexus6p + rtac86u:
        from nexcsi import floating
        floating.unpack = partial(floating.unpack, device=device)
        return floating
    else:
        raise ValueError(
            f"Device '{device}' seems to be an unsupported format. " +
            "Please create a new issue at " +
            "https://github.com/nexmonster/nexcsi/issues " +
            "if you think this is an bug."
        )