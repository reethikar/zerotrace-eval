STARTED_TIME=`date +%s`
tcpdump port not 22 and port not 9100 and not arp -n -i enp1s0f1 -w pcaps/$STARTED_TIME\-packets.pcap &
./example -iface=enp1s0f1 
