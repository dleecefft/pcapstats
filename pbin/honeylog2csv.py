#!/usr/bin/env python
#
# A little utility to split out time stamp and IP address from the simple tcp and udp honey pots.
# CSV seems pretty universal but the RFC5424 time stamp is not the friendliest.
# There is also a challenge with the data payload from the attackers, it's often binary.
# identify the non-ascii bytes and convert to hex values so this data could be feed into Splunk, ELK or
# what ever log analyzer is being used.


import  os, sys, getopt, errno
from datetime import datetime


def tsfixer(tstring):
    tmplist = tstring.strip().split('>')
    tstring = tmplist[1]
    return tstring


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
                newip = ipfixer(rawrow[7])
                csvline = newts + "," + newip
                llist.append(csvline)
    return llist

def writehplog():
    #fh.write(logevthdr + "tcphoneypot: " + logevt + "\n")
    return





if __name__ == "__main__":

    # input and output file data, adjust line grep statements if needed to match a different log line.
    logfile=''
    line1grep = 'Accepted'
    line2grep = 'Recieved'
    logoutlist = []

    # Use getopt to avoid param order errors
    if len(sys.argv) < 4:
        print("Usage: %s -l 2016-04-04_rdphoney -c|-a (csv|ascii_log) " % sys.argv[0])
        exit()
    opts, args = getopt.getopt(sys.argv[1:],"l:c:a:")
    for o, a in opts:
        if o == '-l':
            logfile=a
        elif o == '-c':
            csv = True
            filesfx = '-processed.csv'
        elif o == '-a':
            csv = False
            filesfx = '-processed_ascii.log'
        elif o == '-h':
            print("Usage: %s -l 2016-04-04_rdphoney -c|-a (csv|ascii_log) " % sys.argv[0])
        else:
            print("Usage: %s -l 2016-04-04_rdphoney -c|-a (csv|ascii_log) " % sys.argv[0])

        # open the log file and split
        if csv:
            list2write = readhplogcsv(logfile,logoutlist)
            for lline in list2write:
                print lline

