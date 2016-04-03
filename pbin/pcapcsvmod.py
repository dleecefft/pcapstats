#!/usr/bin/env python
# take a large pcap and dump the data into a CSV so it can be analysed by something like R.
#
# This version we want to know what the source IP is, what the protocol is and based on those
# peices of info run a function to grab that data and write a line to a CSV file
#
#  Ignore all traffic sourced from the self IP, pass self ip as on arg
#  Ignore incoming response traffic
# Prereqs:  pyshark, http://kiminewt.github.io/pyshark/


import pyshark, sys, getopt, csv
from datetime import datetime
from string import maketrans

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


def appendcsv(rlist,cfile):
    # convert ints and
    outputline = ",".join(map(str, rlist))
    with open(cfile,"a") as outputfile:
        outputfile.write(outputline + "\n")
        outputfile.close()
    return


def tcpdecode(lyrlst):
    tmplist=[]
    tmpdict=lyrlst._all_fields
    for key in tmpdict:
        tmplist.append(tmpdict[key])
        wsdecode = "#".join(map(str,tmplist))
        # replace commas in decode with spaces
        transtab = maketrans(","," ")
        wsdecode = wsdecode.translate(transtab)
    return wsdecode


def udpdecode(lyrlst):
    tmplist=[]
    tmpdict=lyrlst._all_fields
    for key in tmpdict:
        tmplist.append(tmpdict[key])
        wsdecode = "#".join(map(str,tmplist))
        # replace commas in decode with spaces
        transtab = maketrans(","," ")
        wsdecode = wsdecode.translate(transtab)
    return wsdecode


def parseTCP(tpkt):
    #print "running parseTCP"
    tmplist = initrow()
    if len(tpkt.layers) > 3:
        # pass to http module
        decoded = tcpdecode(tpkt.layers[3])
        tmplist[8]= str(decoded)
    tmplist[3]= 6
    tmplist[4]= str(tpkt.ip.src).strip()
    tmplist[5]= int(tpkt.tcp.dstport)
    tmplist[6]= int(tpkt.tcp.srcport)
    tmplist[7]= str(tpkt.tcp.flags).strip()
    tsstr=str(tpkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    tmplist[0]= dtobj.strftime("%Y-%m-%d")
    tmplist[1]= dtobj.strftime("%H:%M:%S.%f")
    tmplist[2]= tsstr
    return tmplist


def parseICMP(ipkt):
    #print "running parseICMP"
    tmplist = initrow()
    tmplist[3]= 1
    tmplist[4]= str(ipkt.ip.src).strip()
    tmplist[5]= int(ipkt.icmp.type)
    tmplist[6]= int(ipkt.icmp.code)
    tsstr=str(ipkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    tmplist[0]= dtobj.strftime("%Y-%m-%d")
    tmplist[1]= dtobj.strftime("%H:%M:%S.%f")
    tmplist[2]= tsstr
    return tmplist

def parseUDP(upkt):
    #print "running parseUDP"
    tmplist = initrow()
    if len(upkt.layers) > 3:
        # pass to http module
        decoded = udpdecode(upkt.layers[3])
        tmplist[8]= str(decoded)
    tmplist[3]= 17
    tmplist[4]= str(upkt.ip.src).strip()
    tmplist[5]= int(upkt.udp.dstport)
    tmplist[6]= int(upkt.udp.srcport)
    tsstr=str(upkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    tmplist[0]= dtobj.strftime("%Y-%m-%d")
    tmplist[1]= dtobj.strftime("%H:%M:%S.%f")
    tmplist[2]= tsstr
    return tmplist

def parseIPother(ipopkt):
    tmplist = initrow()
    print "running parseIP Other "
    tmplist[3]= int(ipopkt.ip.proto)
    tmplist[4]= str(ipopkt.ip.src).strip()
    tsstr=str(ipopkt.frame_info.time_epoch)
    dtobj=datetime.fromtimestamp(float(tsstr))
    tmplist[0]= dtobj.strftime("%Y-%m-%d")
    tmplist[1]= dtobj.strftime("%H:%M:%S.%f")
    tmplist[2]= tsstr
    return tmplist

def protorouter(evalpkt):
    # direct
    if int(evalpkt.ip.proto) == 6:
        pktlist = parseTCP(evalpkt)
    elif int(evalpkt.ip.proto) == 1:
        pktlist = parseICMP(evalpkt)
    elif int(evalpkt.ip.proto) == 17:
        pktlist = parseUDP(evalpkt)
    else:
        pktlist = parseIPother(evalpkt)
    return pktlist

#def initrow():
#    # iso-tstamp Date, iso-tstamp Time, epoch-tstamp, proto, src-ip, dest port/type, flag/code
#    rwlist = [str('iso-date'),str('iso-time'),str('epoch-tstamp'),int(6),str('1.2.3.4'),None,None]
#    return  rwlist


def initrow():
    # iso-tstamp Date, iso-tstamp Time, epoch-tstamp, proto, src-ip, dest port/type, flag/code, src port, payload decode
    rwlist = [str('iso-date'),str('iso-time'),str('epoch-tstamp'),int(6),str('1.2.3.4'),None,None,None,None]
    return  rwlist

def parsefilterfile(filtercsv):
    fltrlist=[]
    try:
        ffh = open(filtercsv,'r')
        for line in ffh:
            fltrlist.append(tuple(line.strip().split(',')))
    except Exception , e:
        print e.message
    return fltrlist


def csvwrite(pcapdict,thiscsv):
    # uncomment if you want to watch processing in a cron log
    print pcapdict
    for pkt in pcapdict:
        appendcsv(protorouter(pkt),thiscsv)

