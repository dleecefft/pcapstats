#!/usr/bin/env python
# take a large CSV and filter out service attacks so the duration can be calculated
#
# Take protocol and array of ports as arguments
#
#  Assuming 10 minute buckets for duration, if new traffic seen more than 10 mins
# after last consider it a new gnore all traffic sourced from the self IP, pass self ip as on arg



import  sys, getopt
from datetime import datetime

# input and output files
ifile=''
ofile=''
svcproto=''
svcport=[]

# read command line args and bail if not complete
if len(sys.argv) != 9:
    print("Usage: %s -i input.csv -o output.csv -p 6 -sp 22,80,8080" % sys.argv[0])
    exit()

# Use getopt to avoid param order errors
opts, args = getopt.getopt(sys.argv[1:],"i:o:p:s:")
for o, a in opts:
    if o == '-i':
        ifile=a
    elif o == '-o':
        ofile=a
    elif o == '-p':
        svcproto=a
    elif o == '-s':
        svcport=a
    elif o == '-h':
        print("Usage: %s -i input.csv -o output.csv -p 6 -s 22,80,8080" % sys.argv[0])
    else:
        print("Usage: %s -i input.csv -o output.csv -p 6 -s 22,80,8080" % sys.argv[0])

# Functions

def readcsv(pfile):
    # return a read only file handle
    return open(pfile,"r")

def writecsv(csvfile,outputline):
    with open(csvfile,"a") as outputfile:
        outputfile.write(outputline + "\n")
    return

def newcsvfile(csvfile):
    with open(csvfile,"r") as outputfile:
        outputfile.write("epoch-ip-key,ip_addr,secs_duration\n")
    return


def dictload(clist,cdict):
    ckey = clist[0]
    ip = clist[1]
    ctime = clist[2]
    if ckey not in cdict:
        evtlist = [ip,float(ctime),float(ctime)]
        cdict[ckey]= evtlist
    else:
        # increment the end time if less than 3 hours minutes
        if float(cdict[ckey][2]) < float(ctime):
            cdict[ckey][2] = float(ctime)
    return

def parsedurations(fhdl,proto,svclist):
    print "running parsedurations "
    for line in fhdl:
        llist= line.split(',')
        if llist[3] == proto:
            # parse through services list to filter out all non-service connections
            if int(llist[5]) in svclist:
                #ip,epoch event
                timekey = (int(llist[2].split('.')[0])/10000)
                timekey = str(timekey) + "-" + llist[4]
                tmplist = [timekey,llist[4],llist[2]]
                dictload(tmplist,condict)
    return

def protorouter(evalarg):
    # set boolean for ok to parse
    if int(evalarg) == 6:
        print "running TCP selection"
        return True
    elif int(evalarg) == 17:
        print "running UDP selection"
        return True
    else:
        print "protocol not defined"
    return False

def evalplist(plist):
    protolist=[]
    plist = plist.strip()
    if plist.find(',')!=-1:
        protolist = svcport.split(",")
    elif plist.find(' ')!=-1:
        protolist = svcport.split(" ")
    else:
        protolist.append(plist)
    # map strings to int, try/catch to confirm no funny chars array
    try:
        protolist = map(int,protolist)
    except:
        print "Unexpected error, likely bad characters in list of ports :", sys.exc_info()[0]
        protolist=[]
    return protolist

def initrow():
    # iso-tstamp Date, iso-tstamp Time, epoch-tstamp, proto, src-ip, dest port/type, flag/code
    rwlist = [str('iso-date'),str('iso-time'),str('epoch-tstamp'),int(6),str('1.2.3.4'),None,None]
    return  rwlist


# Main flow
thiscsv = readcsv(ifile)
# dictionary
condict = {}
# select just the protocol passed
if (protorouter(svcproto)):
    thisplist = evalplist(svcport)
    if len(thisplist) > 0:
        parsedurations(thiscsv,svcproto,thisplist)

# create  new csv file with a header
newcsvfile(ofile)

# write the remainder to the CSv
for ipkey in condict:
    duration = float(condict[ipkey][2]) -   float(condict[ipkey][1])
    csvline = ipkey + "," + str(condict[ipkey][0]) + "," + str(duration)
    writecsv(ofile,csvline)
    #print ipkey + " " + str(condict[ipkey][0]) + " duration: " +  str(condict[ipkey][2]) + " - " + str(condict[ipkey][1]) + " " + str(duration)
#
