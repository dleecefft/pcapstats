#!/usr/bin/env python
# A simple lure that accepts coommand line args for listening port, IP address and log file
# This should be completly detectable by a human but an automated probe might waste some time
# the log file is to grab logs to assist with profiling.
# Create a new log every day, through naming?
#
# Credits:
# Borrows heavily from Justin Sietz Blackhat python, some smart folks in Canada :-)

import socket, threading, os, sys, getopt, errno
from datetime import datetime

def datelogprefix():
    now=datetime.now()
    logdatepre = now.strftime("%Y-%m-%d")
    return logdatepre


def writelog(logsfx,logevt):
    #Get the time stamp as soon as possible
    tstamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%m:%S.%fZ")
    # This log directory is hard coded based on a check at runtime, change in both places if you need to move it
    # builds a new log file everyday the honey pot sees activity so it is easier to find event data
    thislog = "/var/tmp/hpotlogs/" + datelogprefix() + "_" + logsfx
    # write events in 5424 syslog format so other tools may be able to ingest add TZ info if really needed
    # local 0, notice https://tools.ietf.org/html/rfc5424#page-11
    # broke the timestamp for fidelity, milliseonds are helpful,
    logevthdr ="<133>" + str(tstamp) + hname

    wmode = 'ab+'
    if os.path.exists(thislog):
        wmode = 'ab+'
    else:
        wmode = 'w+'
    with open(thislog,wmode) as fh:
        fh.write(logevthdr + "tcphoneypot: " + logevt + "\n")
    return

def handle_client(client_socket):
    req = client_socket.recv(1024)
    logstring = "Recieved data %s" % req
    writelog(logfile,logstring)
    # acknowledge and quit
    client_socket.send("ACK!")
    client_socket.close()

def runserver():
    while True:
        client,addr = tcpserver.accept()
        logstring = "Accepted connection from %s:%d" % (addr[0],addr[1])
        writelog(logfile,logstring)
        client_handler = threading.Thread(target=handle_client,args=(client,))
        client_handler.start()

if __name__ == "__main__":

    # input and output files
    listenip=''
    listenport=''
    logfile=''
    # Use getopt to avoid param order errors
    if len(sys.argv) != 7:
        print("Usage: %s -i 198.51.100.99 -p 3389 -l rdphoney.log" % sys.argv[0])
        exit()
    opts, args = getopt.getopt(sys.argv[1:],"i:p:l:")
    for o, a in opts:
        if o == '-i':
            listenip=a
        elif o == '-p':
            listenport=int(a)
        elif o == '-l':
            logfile=a
        elif o == '-h':
            print("Usage: %s -i 198.51.100.99 -p 3389 -l rdphoney.log" % sys.argv[0])
        else:
            print("Usage: %s -i 198.51.100.99 -p 3389 -l rdphoney.log" % sys.argv[0])

    # need a default spot to place honeypot logs, make group writeable if you have a few users running them
    d = "/var/tmp/hpotlogs"
    if not os.path.exists(d):
        os.mkdir(d,0770)
    # hostname with a leading space and a following space, make it once
    hname = " " + socket.gethostname() + " "

    tcpserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        tcpserver.bind((listenip,listenport))
    except socket.error, v:
        errorcode=v[0]
        # long run we should do a netstat and confirm the IP and port are legit and not running, advise user then bail.
        print errorcode
        raise

    try:
        tcpserver.listen(12)  # a dozen backlog should be plenty but check, auto scanners are aggressive.
        logstring = "Listening on %s:%d" % (listenip,listenport)
        writelog(logfile,logstring)
    except socket.error, v:
        errorcode=v[0]
        # assuming this worked above this should never fire so leave messy.
        print errorcode
        raise

    runserver()