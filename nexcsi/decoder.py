rpi = ["rpi", "raspberrypi", "rpi4", "rpi3", "bcm43455c0", "bcm43455"]
nexus5 = ["nexus5", "bcm4339"]


def decoder(key):
    if key in rpi or nexus5:
        from nexcsi import interleaved
        return interleaved
    else:
        raise ValueError(
            f"'{key}' seems to be an unsupported format. " +
            "Please create a new issue at " +
            "https://github.com/nexmonster/nexcsi/issues " +
            "if you think this is an bug."
        )