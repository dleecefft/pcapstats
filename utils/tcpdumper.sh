#!/usr/bin/env bash
#  simple script to setup up TCP dump to rotate hourly, name it correctly, sniff correct interface and ignore all traffic
#  to and from the admin server

# too lazy to go with get opt, program will just blow up with bad values, good enough for whaat this is supposed to be

# Apr 3/2016  added filtering and nohup so it's a little more portable

if [[ "$#" -lt 3 ]] ; then
   echo " usage: tcpdumper.sh interface hostname adminhost-to-ignore"
   echo " tcpdumper.sh eth0 server42 187.12.34.10"
   echo " note:  passing 5 args will allow filering on monitored interface"
   echo " usage: tcpdumper.sh interface hostname adminhost-to-ignore host_or_net host_or_cidr-to-monitor"
   exit 1
fi

SNIF=$1
THISHOST=$2
ADMIN=$3
MONTYPE=$4
MONSPEC=$5

if [[ ! -e /var/tmp/pcapstats ]] ; then
    mkdir /var/tmp/pcapstats
fi

# test to make sure directory exists,  since this needs to run as root no need to test for writable

if [[ -d /var/tmp/pcapstats ]] ; then
   # need to add a line for specific host or network to watch, good for multi-home with a back channel like a NIDS sensor
   if [[ -z ${MONTYPE} ]]; then
        /usr/bin/nohup /usr/sbin/tcpdump -nn -i ${SNIF} -w /var/tmp/pcapstats/${THISHOST}_%Y%m%d%H%M.pcap -G 3600 not host ${ADMIN}  &
   else
        /usr/bin/nohup /usr/sbin/tcpdump -nn -i ${SNIF} -w /var/tmp/pcapstats/${THISHOST}_%Y%m%d%H%M.pcap -G 3600 \
         ${MONTYPE} ${MONSPEC} and  not host ${ADMIN} &
   fi

else
    echo " can't write pcaps to /var/tmp/pcapstats , investigate "
    exit 1
fi