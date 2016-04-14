#!/usr/bin/env python

from scapy.all import *
import re, sys, getopt, shutil


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
    retlist.append(tmpip[1])
    tmpip = sssnlist[3].split(':')
    retlist.append(tmpip[0])
    retlist.append(tmpip[1])
    return retlist


def partstrsplit(ipportstr):
    retlist=[]
    sssnlist = ipportstr.split()
    # stack up the list and split out the port values
    retlist.append(sssnlist[0])
    retlist.append(sssnlist[1])
    retlist.append('')
    retlist.append(sssnlist[3])
    retlist.append('')
    return retlist

def writesessioncsv(fileline,wfile):
    try:
        with open(wfile,'a') as wfh:
            wfh.write(fileline + "\n")
    except Exception as e:
        print(e)
        pass
    return


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
            ksplit = partstrsplit(k)
            kline = ','.join(map(str,ksplit))
            kline = kline +"," + str(len(v))
            print kline
            #print k,str(len(v))
    return

def sessionparsewrite(ssnobj,include,pktgrep,csvoutfile):
    sessions = ssnobj.sessions()

    for k, v in sessions.iteritems():

        rxparse = re.match(r'^\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}).*\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})',k)

        if include and rxparse is not None:
            # looking for a match
            if rxparse.group(1) == pktgrep or rxparse.group(2) == pktgrep :
                ksplit = fullstrsplit(k)
                kline = ','.join(map(str,ksplit))
                kline = kline +"," + str(len(v))
                writesessioncsv(kline,csvoutfile)
        elif rxparse is not None:
            if rxparse.group(1) != pktgrep and rxparse.group(2) != pktgrep :
                #print k,str(len(v))
                ksplit = fullstrsplit(k)
                kline = ','.join(map(str,ksplit))
                kline = kline +"," + str(len(v))
                writesessioncsv(kline,csvoutfile)

        elif not include and rxparse is None:
            ksplit = partstrsplit(k)
            kline = ','.join(map(str,ksplit))
            kline = kline +"," + str(len(v))
            writesessioncsv(kline,csvoutfile)
            #print k,str(len(v))
    return


if __name__ == "__main__":

    if len(sys.argv) > 3 :
        action=''
        outcsv=False
        # Use getopt to avoid param order errors
        opts, args = getopt.getopt(sys.argv[1:],"f:m:o:t:h:")
        for o, a in opts:
            if o == '-f':
                capfile=a
            elif o == '-m':
                strmatch=a
            elif o == '-o':
                outfile=a
                outcsv=True
            elif o == '-t':
                action=a
            else:
                print("Usage: %s -f file.pcap -m ip:port_string -o [outputfile] -t [exclude] <- ignore these sessions " % sys.argv[0])
                exit()
    else:
        print("Usage: %s -f file.pcap -m ip:port_string -o [outputfile] -t [exclude] <- ignore these sessions " % sys.argv[0])
        exit()
    # default action is search for string provided vs exclude
    if action == "exclude":
        action=False
    else:
        action=True

    # grab sessions from pcap
    thisssnobj = pcapsessions(capfile)
    if outcsv:
        sessionparsewrite(thisssnobj,action,strmatch,outfile)
    else:
        sessionparse(thisssnobj,action,strmatch)

