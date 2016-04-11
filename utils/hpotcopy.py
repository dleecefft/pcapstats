#!/usr/bin/env python
# Determine the current date in iso format and copy everything but those
# files starting with the date.  Shouldn't collide because the honey pot
# checks the date before writing to a file.  Cron it sometime after midnight.
#
# The pcap job is in bash but this is more complicated, could have many honey pot logs
# it's kind of lame shelling out but this is a one time a day job, performance no big deal


import os, sys, getopt,re
from datetime import datetime
from datetime import date


# define user account for transfer and location of key, these defaults can be overriden by command line params
USER='hptester'
KEY='/home/hptester/.ssh/id_rsa'
SDIR='/var/tmp/hpotlogs'
ADIR= SDIR + "/archive"
DHOST='north.balam.ca' # should work as ip as well
DDIR='/opt/hpdata/south'
FMATCH ='honey'


def archivefile(shippedfile):
    print "moving " + shippedfile + " to " + ADIR
    return


def remotecopy(curfile):
    # build command to execute
    #echo "scp -i ${KEY} ${pcap} $USER@${DHOST}$DDIR "
    #b = "i am a {0}".format(sub1)
    print('scp -i {0} '.format(KEY,) + curfile + ' {0}@{1}:{2}/'.format(USER,DHOST,DDIR))
    #os.system("scp ")
    # check copy status, if copied ok
    archivefile(curfile)
    return


def logfilelist(srcdir,fnamegrep):
    # need enough in the fname grep arg to id the correct files
    # hopefully this ok, passing regex in a function seems frail, pick a clean directory
    filepre = gettodayiso()
    return


def gettodayiso():
    dt = datetime.now()
    isodate = date.isoformat(dt)
    return isodate


def fileslug(greptoken):
    slug = '\d\d\d\d-\d\d-\d\d_.*'+greptoken
    # clumsy but looks simpler to pass to regex compile
    slug = "r'" + slug +"'"
    return slug


def copynarch(src,arch,dst,hst,fmt):
    if os.path.isdir(src):
        # assuming a relativly clean directory so grabbing all and filtering after instead of during collection
        files=os.listdir(src)
        if len(files) > 0:
            # define the string to match files that are most likely to be honeypot files
            filepat = fileslug(fmt)
            filepre = re._compile(filepat)
            for thisfile in files:
                print thisfile
                if re.search(filepre,thisfile ) and os.path.isfile(thisfile):
                    remotecopy(thisfile)
                else:
                    print "No files in the directory provided"
        else:
            print("Sorry, %s does not appear to be a valid directory. Exiting now" % SDIR)


        return


if __name__ == "__main__":

    # option to override certain params if
    if len(sys.argv) > 1:
        # Use getopt to avoid param order errors
        opts, args = getopt.getopt(sys.argv[1:],"s:d:a:f:t:")
        for o, a in opts:
            if o == '-s':
                SDIR=a
            elif o == '-d':
                DDIR=a
            elif o == '-a':
                ADIR=a
            elif o == '-f':
                FMATCH =a
            elif o == '-t':
                DHOST = a
            elif o == '-h':
                print "All params are optional, can be set in top of file for daily archive job"
                print("Usage: %s -s log-source_dir -a log_archive_dir -d remote_destination_dir -t remote_host" % sys.argv[0])
            else:
                print("Usage: %s -s log-source_dir -a log_archive_dir -d remote_destination_dir -t remote_host" % sys.argv[0])

    # need to catch a few things like is this a real directory and does it contain any files that match the format
    copynarch(SDIR,ADIR,DDIR,DHOST,FMATCH)
