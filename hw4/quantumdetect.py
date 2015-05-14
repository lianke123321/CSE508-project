#!/usr/bin/python
import sys, getopt
from collections import deque
from scapy.all import *

pkt_fifo = deque(maxlen = 10)

def handle_packet(pkt):
    #print 'I\'m in!'
    # only care about tcp packet
    
    if pkt.haslayer(TCP):
        if len(pkt_fifo) > 0:
            #print 'Current number of cached packet:', len(pkt_fifo)
            # compare the fields with pkts in fifo
            for old_pkt in pkt_fifo:
                # compare with each one
                if old_pkt[IP].src == pkt[IP].src and\
                old_pkt[IP].dst == pkt[IP].dst and\
                old_pkt[TCP].sport == pkt[TCP].sport and\
                old_pkt[TCP].dport == pkt[TCP].dport and\
                old_pkt[TCP].seq == pkt[TCP].seq and\
                old_pkt[TCP].ack == pkt[TCP].ack and\
                len(old_pkt[TCP]) > 32 and\
                len(pkt[TCP]) > 32 and\
                old_pkt[TCP].chksum != pkt[TCP].chksum:
                    print '\n\tFound MotS Attack! Cached packet:\n'
                    print old_pkt.show()
                    print '\n\tNewly arrived duplicated packet:\n'
                    print pkt.show()
        
        pkt_fifo.append(pkt)
    '''
    if TCP in pkt:
        ls(pkt)
    '''
    #return packet.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}")

def main(argv):
    interface = ''
    filename = ''
    expression = ''
    
    try:
        opts, args = getopt.getopt(argv, 'i:r::')
    except getopt.GetoptError:
        print 'usage: python quantumdetect.py -i <interface> <optional expression>'
        print '   or: python quantumdetect.py -r <filename> <optional expression>'
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-i':
            interface = arg
        elif opt == '-r':
            filename = arg
    
    if len(args) == 1:
        expression = args[0]
    elif len(args) > 1:
        print '\n\tMore non-option arguments than expected!\n'
        sys.exit()
    
    print '\n\tInitializing quantum detector using following parameters:\n',\
        '\t\tinterface:', interface, '\n',\
        '\t\tdata file:', filename, '\n',\
        '\t\texpression:', expression, '\n'
    
    if interface != '' and filename != '':
        print 'Please only use interface OR file name!\n'
        sys.exit()
    elif interface == '' and filename == '':
        print '\tSniffing on all interfaces by default'
        sniff(prn = handle_packet, filter = expression)
    elif interface != '' and filename == '':
        print '\tSniffing on interface', interface
        sniff(iface = interface, prn = handle_packet, filter = expression)
    else:
        print '\tSniffing offline trace file', filename
        sniff(offline = filename, prn = handle_packet, filter = expression)
    
    #sniff(iface=interface, prn=http_header, filter="tcp port 80")

if __name__ == "__main__":
    main(sys.argv[1:])