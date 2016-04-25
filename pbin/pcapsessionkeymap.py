#!/usr/bin/env python

from scapy.all import *
import re, sys, getopt, shutil, csv



def writereducedcsv(mapreddict,wfile):
    try:
        with open(wfile,'wb') as wfh:
            csvwrt = csv.writer(wfh, delimiter=',')
            csvwrt.writerow(["IP-port_key","bytes rec","byte resp"])
            for key, value in mapreddict.items():
                csvwrt.writerow(key + value[0] + value[1])
    except Exception as e:
        print(e)
        pass
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
        # Use getopt to avoid param order errors
        opts, args = getopt.getopt(sys.argv[1:],"f:m:o:")
        for o, a in opts:
            if o == '-f':
                splitfile=a
            elif o == '-m':
                strmatch=a
            elif o == '-o':
                reducedcsv=a
            else:
                print("Usage: %s -f sessionfile.csv -m ip:port_string -o outputfile.csv" % sys.argv[0])
                exit()
    else:
        print("Usage: %s -f sessionfile.csv -m ip:port_string -o outputfile.csv" % sys.argv[0])
        exit()

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
    # generate the CSV file with a proper header, ip-port key, bytes from unknown, bytes responded
    # note this is not an exact byte value, it's relative, there is some paddingthat scapy puts in but we
    # don't known the traffic in advance so for graphing we'll leave as is
    writereducedcsv(mapreduced,reducedcsv)

