#!/usr/bin/env python

from scapy.all import *
import re, sys, getopt

if len(sys.argv) < 4 :
    print "three args dude "
    exit()

pcapfile=sys.argv[1]
pktgrep = sys.argv[2]
include= sys.argv[3]

include=True

def pcapsessions(pfile):
    pssn = rdpcap(pfile)
    return pssn

def fullstrsplit(ipportstr):
    retlist=[]
    sssnlist = ipportstr.split()
    # stack up the list and split out the port values
    retlist.append(sssnlist[0])
    tmpip = sssnlist[1].split(':')
    retlist.append(tmpip[0])
    retlist.append(tmpip[3])
    tmpip = sssnlist[1].split(':')
    retlist.append(tmpip[0])
    retlist.append(tmpip[1])
    return retlist


def partstrsplit(ipportstr):
    retlist=[]
    sssnlist = ipportstr.split()
    # stack up the list and split out the port values
    retlist.append(sssnlist[0])
    retlist.append(sssnlist[1])
    retlist.append(sssnlist[3])
    #tmpip = sssnlist[1].split(':')
    #retlist.append(tmpip[0])
    #retlist.append(tmpip[3])
    #tmpip = sssnlist[1].split(':')
    #retlist.append(tmpip[0])
    #retlist.append(tmpip[1])
    return retlist


def sessionparse(ssnobj,include,pktgrep):
    sessions = ssnobj.sessions()

    for k, v in sessions.iteritems():

        rxparse = re.match(r'^\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}).*\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})',k)

        if include and rxparse is not None:
            # looking for a match
            if rxparse.group(1) == pktgrep or rxparse.group(2) == pktgrep :
                ksplit = fullstrsplit(k)
                kline = ','.join(map(str,ksplit))
                kline = kline +"," + str(len(v))
                print kline
                #print k,str(len(v))
        elif rxparse is not None:
            if rxparse.group(1) != pktgrep and rxparse.group(2) != pktgrep :
                #print k,str(len(v))
                ksplit = fullstrsplit(k)
                kline = ','.join(map(str,ksplit))
                kline = kline +"," + str(len(v))
                print kline
        elif not include and rxparse is None:
            print k,str(len(v))


if __name__ == "__main__":

# option to override certain params if
    if len(sys.argv) < 2 :
        # Use getopt to avoid param order errors
        opts, args = getopt.getopt(sys.argv[1:],"f:m:o:t:h:")
        for o, a in opts:
            if o == '-f':
                capfile=a
            elif o == '-m':
                strmatch=a
            elif o == '-o':
                outfile=a
            elif o == '-t':
                action=a
            elif o == '-h':
                print("Usage: %s -f file.pcap -m ip:port_string -o [outputfile] " % sys.argv[0])
                exit()
            else:
                print("Usage: %s -f file.pcap -m ip:port_string -o [outputfile] " % sys.argv[0])
                exit()
    if action == "exclude":
        action=False
    else:
        action == True

    # grab sessions from pcap
    thisssnobj = pcapsessions(capfile)
    sessionparse(thisssnobj,action,strmatch)

