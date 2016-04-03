#!/usr/bin/env bash
#
# define user account for transfer and location of key
USER=hptester
KEY=/home/hptester/.ssh/id_rsa
WDIR=/var/tmp/hpdata
DHOST=north.balam.ca # should work as ip as well
DDIR=/opt/hpdata/south
# get tcpdump pid
TPID=`/usr/bin/pgrep -f /usr/sbin/tcpdump`

echo $TPID

if [[ ! -d ${WDIR}/old ]] ; then
    /bin/mkdir ${WDIR}/old
fi


#  get file descriptor
VAR=`ls -l  /proc/${TPID}/fd | grep $WDIR | awk '{print $11}'`
for pcap in `ls ${WDIR}/*.pcap` ; do
    if [[ ${pcap} !=  ${VAR} ]] ; then
       echo "scp -i ${KEY} ${pcap} $USER@${DHOST}$DDIR "
       /usr/bin/scp  -B -i ${KEY} ${pcap} $USER@${DHOST}:${DDIR}/
       /bin/mv ${pcap} ${WDIR}/old/
    else
       echo "matched "
    fi
done