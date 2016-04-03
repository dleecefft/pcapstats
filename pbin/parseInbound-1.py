#!/usr/bin/env python
# take a large pcap and dump the data into a CSV so it can be analysed by something like R.
#
# This version we want to know what the source IP is, what the protocol is and based on those
# peices of info run a function to grab that data and write a line to a CSV file
#
#  Ignore all traffic sourced from the self IP, pass self ip as on arg
#  Ignore incoming response traffic
# Prereqs:  pyshark, http://kiminewt.github.io/pyshark/


import pyshark, sys, getopt
from datetime import datetime

# input and output files
ifile=''
ofile=''
selfip=''

# read command line args and bail if not complete
if len(sys.argv) != 7:
    print("Usage: %s -i input.pcap -o output.csv -s 192.168.100.6" % sys.argv[0])
    exit()

# Use getopt to avoid param order errors
opts, args = getopt.getopt(sys.argv[1:],"i:o:s:")
for o, a in opts:
    if o == '-i':
        ifile=a
    elif o == '-o':
        ofile=a
    elif o == '-s':
        selfip=a
    elif o == '-h':
        print("Usage: %s -i input.pcap -o output.csv -s 192.168.100.6" % sys.argv[0])
    else:
        print("Usage: %s -i input.pcap -o output.csv -s 192.168.100.6" % sys.argv[0])

# Functions

def readpcap(pfile):
    return pyshark.FileCapture(pfile,"keep_packets"==False)
    #return pyshark.FileCapture(pfile)

def epochconv(tsstr):
    # convert the frame time into iso via epoch, clumsy but works better for excel
    # return list so we can have both in the CSV, epoch and friendly
    retlist=[]
    dtobj=datetime.fromtimestamp(float(tsstr))
    retlist.append(str(dtobj).strip())
    retlist.append(tsstr.strip())
    return retlist

def appendcsv(rlist):
    # convert ints and
    outputline = ",".join(map(str, rlist))
    with open(ofile,"a") as outputfile:
        outputfile.write(outputline + "\n")
    return

def parseTCP(tpkt):
    #print "running parseTCP"
    rowlist[3]= 6
    rowlist[4]= str(tpkt.ip.src).strip()
    rowlist[5]= int(tpkt.tcp.dstport)
    rowlist[6]= str(tpkt.tcp.flags).strip()
    tsstr=str(tpkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    rowlist[0]= dtobj.strftime("%Y-%m-%d")
    rowlist[1]= dtobj.strftime("%H:%M:%S.%f")
    rowlist[2]= tsstr
    return

def parseICMP(ipkt):
    #print "running parseICMP"
    rowlist[3]= 1
    rowlist[4]= str(ipkt.ip.src).strip()
    rowlist[5]= int(ipkt.icmp.type)
    rowlist[6]= int(ipkt.icmp.code)
    tsstr=str(ipkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    rowlist[0]= dtobj.strftime("%Y-%m-%d")
    rowlist[1]= dtobj.strftime("%H:%M:%S.%f")
    rowlist[2]= tsstr
    return

def parseUDP(upkt):
    #print "running parseUDP"
    rowlist[3]= 17
    rowlist[4]= str(upkt.ip.src).strip()
    rowlist[5]= int(upkt.udp.dstport)
    rowlist[6]= int(upkt.udp.srcport)
    tsstr=str(upkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    rowlist[0]= dtobj.strftime("%Y-%m-%d")
    rowlist[1]= dtobj.strftime("%H:%M:%S.%f")
    rowlist[2]= tsstr
    return

def parseIPother(ipopkt):
    print "running parseIP Other "
    rowlist[3]= int(ipopkt.ip.proto)
    rowlist[4]= str(ipopkt.ip.src).strip()
    tsstr=str(ipopkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    rowlist[0]= dtobj.strftime("%Y-%m-%d")
    rowlist[1]= dtobj.strftime("%H:%M:%S.%f")
    rowlist[2]= tsstr
    return

def protorouter(evalpkt):
    # direct
    if int(evalpkt.ip.proto) == 6:
        parseTCP(evalpkt)
    elif int(evalpkt.ip.proto) == 1:
        parseICMP(evalpkt)
    elif int(evalpkt.ip.proto) == 17:
        parseUDP(evalpkt)
    else:
        parseIPother(evalpkt)
    return

def initrow():
    # iso-tstamp Date, iso-tstamp Time, epoch-tstamp, proto, src-ip, dest port/type, flag/code
    rwlist = [str('iso-date'),str('iso-time'),str('epoch-tstamp'),int(6),str('1.2.3.4'),None,None]
    return  rwlist


# Main flow
thiscap = readpcap(ifile)
wrstat = True
# cheat making a global
rowlist=[]
for pkt in thiscap:
    pktsrc = str(pkt.ip.src)
    if pktsrc != selfip:
        #reinit array
        rowlist = initrow()
        protorouter(pkt)
        # time stamp cast as a string to retain precision and simplify function
        #tslist=epochconv(str(pkt.frame_info.time_epoch))
        #rowlist[0]= tslist[0]
        #rowlist[1]= tslist[1]
        appendcsv(rowlist)
