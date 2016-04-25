#!/usr/bin/env python

from scapy.all import *
import re, sys, getopt, shutil, csv


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

def writereducedcsv(mapreddict,wfile):
    try:
        with open(wfile,'wb') as wfh:
            csvwrt = csv.writer(wfh, delimiter=',')
            csvwrt.writerow(["IP-port_key","bytes rec","byte resp"])
            for key, value in mapreddict.items():
                bytesinout = value.split(',')
                csvwrt.writerows(key + bytesinout[0] + bytesinout[1])
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

# two functions to add to the running dictionary
def recvdictadd(kvlist,recd):
    k = kvlist[0]
    v = kvlist[1]
    if k not in recd:
        recd[k] = v
    else:
        recd[k] = recd[k] + v
    return recd

def rplvdictadd(kvlist,rpld):
    k = kvlist[0]
    v = kvlist[1]
    if k not in rpld:
        rpld[k] = v
    else:
        rpld[k] = rpld[k] + v
    return rpld

def mapsessionbykey(ssncsv,smtch,drec,drly):
    keyvallist = []
    with open(ssncsv,'r') as rfh:
        for line in rfh:
            linelist = line.split(',')
            if str(linelist[1] + ":" + linelist[2]) == smtch:
                thiskey = linelist[3] + "-" + linelist[4]
                keyvallist = [thiskey, int(linelist[5])]
                drly = rplvdictadd(keyvallist,drly)
            else:
                thiskey = linelist[1] + "-" + linelist[2]
                keyvallist = [thiskey, int(linelist[5])]
                #print keyvallist
                drec = recvdictadd(keyvallist, drec)
    # return the two completed dictionaries
    retlist = [drec,drly]
    return retlist



if __name__ == "__main__":

    if len(sys.argv) > 3 :
        #action=''
        #outcsv=False
        # Use getopt to avoid param order errors
        opts, args = getopt.getopt(sys.argv[1:],"f:m:o:")
        for o, a in opts:
            if o == '-f':
                splitfile=a
            elif o == '-m':
                strmatch=a
            elif o == '-o':
                reducedcsv=a
                #outcsv=True
            #elif o == '-r':
            #    datarply=a
                #outcsv=True
            #elif o == '-t':
            #    action=a
            else:
                print("Usage: %s -f sessionfile.csv -m ip:port_string -o outputfile.csv" % sys.argv[0])
                exit()
    else:
        print("Usage: %s -f sessionfile.csv -m ip:port_string -o outputfile.csv" % sys.argv[0])
        exit()
    # default action is search for string provided vs exclude
    #if action == "exclude":
    #    action=False
    #else:
    #    action=True

    # grab sessions from pcap
    #thisssnobj = pcapsessions(capfile)
    #if outcsv:
    # two dictionaries to hold the keys
    datarecdict = {}
    datarpldict = {}

    # one main function to generate the two files
    # returns a list of two dictionaries
    recrpldicts = mapsessionbykey(splitfile,strmatch,datarecdict,datarpldict)

    # use the ip-port key for map reduction, capture non-responses as 0. ( Ignores possiblity of unsolicited outbound traffic )
    mapreduced = {}
    for ky,vl in recrpldicts[0].iteritems():
        rplv = "0"
        if recrpldicts[1][ky]:
            rplv = str(recrpldicts[1][ky])
        bytevals =[str(vl),rplv]
        mapreduced[ky] = bytevals

    writereducedcsv(mapreduced,reducedcsv)

