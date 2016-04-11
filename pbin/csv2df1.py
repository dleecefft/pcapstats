#!/usr/bin/env python
#
import  os, sys, getopt
from datetime import datetime






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
        print("Usage: %s -l 2016-04-04_rdphoney -f csv | ascii_log [-w outputfilei]) " % sys.argv[0])
        exit()
    opts, args = getopt.getopt(sys.argv[1:],"l:f:w:")
    for o, a in opts:
        if o == '-l':
            logfile=a
        elif o == '-f':
            outformat=a
        elif o == '-w':
            writefile = True
            outfile =a
        elif o == '-h':
            print("Usage: %s -l 2016-04-04_rdphoney -f (csv|ascii_log) [ -w outputfileprefix ] " % sys.argv[0])
        else:
            print("Usage: %s -l 2016-04-04_rdphoney -f (csv|ascii_log) [ -w outputfileprefix ] " % sys.argv[0])