#!/usr/bin/env python
#
# A little utility to split out time stamp and IP address from the simple tcp and udp honey pots.
# CSV seems pretty universal but the RFC5424 time stamp is not the friendliest.
# There is also a challenge with the data payload from the attackers, it's often binary.
# identify the non-ascii bytes and convert to hex values so this data could be feed into Splunk, ELK or
# what ever log analyzer is being used.


import  os, sys, getopt, errno
from datetime import datetime
from datetime import date
from datetime import time


def tsfixer(tstring):
    tmplist = tstring.strip().split('>')
    tstring = tmplist[1]
    dt = datetime.strptime(tstring,'%Y-%m-%dT%H:%M:%S.%fZ')
    millitstamp = int((dt - epoch).total_seconds() * 1000)
    # strip out iso date and time as well
    isodate = date.isoformat(dt)
    isotime = dt.time()
    tstringlist=[tstring,millitstamp,isodate,isotime]

    return tstringlist


def ipfixer(ipstring):
    tmplist = ipstring.strip().split(':')
    ipstring = tmplist[0]
    return ipstring


def readhplogcsv(thislog,llist):
    with open(thislog,'r') as fh:
        # try to do this in place to save ram and time on large files
        for line in fh:
            if line1grep in line:
                rawrow = line.strip().split(' ')
                newts = tsfixer(rawrow[0])
                newip = ipfixer(rawrow[6])
                csvline = str(newts[1]) + "," + newts[0] + "," + str(newts[2]) + ","  + str(newts[3]) + "," + newip
                llist.append(csvline)
        llist.sort()
    return llist

def writehplog(linelist,wfile):
    with open(wfile,'w') as wfh:
        for line in linelist:
            wfh.write(line)
    #fh.write(logevthdr + "tcphoneypot: " + logevt + "\n")
    return





if __name__ == "__main__":

    # input and output file data, adjust line grep statements if needed to match a different log line.
    logfile=''
    line1grep = 'Accepted'
    line2grep = 'Recieved'
    logoutlist = []
    csv = True
    writefile = False
    outfile='parsedhpotlog'
    # Need the epoch object to make millisecond timestamps
    epoch = datetime.utcfromtimestamp(0)

    # Use getopt to avoid param order errors
    if len(sys.argv) < 4:
        print("Usage: %s -l 2016-04-04_rdphoney -c csv | -a ascii_log [-w outputfile) " % sys.argv[0])
        exit()
    opts, args = getopt.getopt(sys.argv[1:],"l:c:a:w")
    for o, a in opts:
        if o == '-l':
            logfile=a
        elif o == '-c':
            csv = True
            filesfx = '-processed.csv'
        elif o == '-a':
            csv = False
            filesfx = '-processed_ascii.log'
        elif o == '-w':
            writefile = True
            outfile =a
        elif o == '-h':
            print("Usage: %s -l 2016-04-04_rdphoney -c|-a (csv|ascii_log) " % sys.argv[0])
        else:
            print("Usage: %s -l 2016-04-04_rdphoney -c|-a (csv|ascii_log) " % sys.argv[0])

        # open the log file and split
        if csv:
            list2write = readhplogcsv(logfile,logoutlist)
            if writefile:   # write to output file if argument given else push to std out
                fname = outfile + filesfx
                writehplog(list2write,fname)
            else:
                for lline in list2write:
                    print lline

