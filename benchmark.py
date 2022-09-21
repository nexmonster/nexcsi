import timeit

print(
    timeit.timeit(
        "interleaved.read_pcap('./output100k.pcap')",
        setup="from nexcsi import interleaved",
        number=100,
    )
)
