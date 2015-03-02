import pcapy

reader = pcapy.open_offline("hw1.pcap")

while True:
    try:
        (header, payload) = reader.next()
        print header.getlen()
    except pcapy.PcapError:
        break