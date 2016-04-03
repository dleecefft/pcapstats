#!/usr/bin/env python
# read a directoy of pcaps and and dump the data into a CSV so it can be analysed by something like R.
#
# Implement as a daily cron job to make data sets for analysis.
# Provide a directory of pcaps, a destination file path & prefix, optional csv file of connections to ignore
# #  Ignore incoming response traffic
# Prereqs:  pyshark, http://kiminewt.github.io/pyshark/


import getopt
import os
import pcapcsvmod
import shutil
import sys
from datetime import date


def pcapdirlist(pcapdir):
    pcaplist = []
    dirlist = os.listdir(pcapdir)
    for dirfile in dirlist:
        if dirfile.endswith('.pcap'):
            truefile = os.path.realpath(pcapdir + "/" + dirfile)
            if os.path.isfile(truefile):
                pcaplist.append(truefile)
    return pcaplist

def mkfilename(fileprefix):
    todate=date.today()
    day = '%02d' % todate.day
    mth = '%02d' % todate.month
    isodaystr=str(todate.year) + mth + day
    filestr = fileprefix + "_" + isodaystr + ".csv"
    return filestr

def archiveprocessed(fileprefix,abslist):
    archdir = fileprefix + "/processed"
    print archdir
    if os.path.isdir(archdir):
        print "archving " + str(len(abslist)) + " pcap files"
        for absfile in abslist:
            try:
                shutil.move(absfile,archdir)
            except Exception , e:
                print e.message
    else:
        try:
            os.mkdir(archdir,0700)
            if os.path.isdir(archdir):
                print "archiving " + str(len(abslist)) + " pcap files"
            for absfile in abslist:
                try:
                    shutil.move(absfile,archdir)
                except Exception , e:
                    print e.message
        except:
            print "unable to make directory"




def programflow():
    # read command line args and bail if not complete
    if len(sys.argv) < 4:
        print("Usage: %s -i input_pcap.dir -o output_path_prefix [ -f filtered_conns.csv ]" % sys.argv[0])
        exit()
    # Use getopt to avoid param order errors
    opts, args = getopt.getopt(sys.argv[1:],"i:o:f:")
    for o, a in opts:
        if o == '-i':
            indir=a
        elif o == '-o':
            outpre=a
        elif o == '-f':
            filterlist =a
        elif o == '-h':
            print("Usage: %s -i input_pcap.dir -o output_path_prefix [ -f filtered_conns.csv ] " % sys.argv[0])
        else:
            print("Usage: %s -i input_pcap.dir -o output_path_prefix [ -f filtered_conns.csv ]" % sys.argv[0])
    # Collect all pcaps from the defined directory
    pcaplist = pcapdirlist(indir)
    # format the output csv
    proccsv = mkfilename(outpre)
    # process the filter
    #flist =
    # Open each pcap file and process it
    for filecap in pcaplist:
        thisfilecap = pcapcsvmod.readpcap(filecap)
        pcapcsvmod.csvwrite(thisfilecap, proccsv)
    # move processed files
    archiveprocessed(indir,pcaplist)




#if __name__ == '__main__':
programflow()
