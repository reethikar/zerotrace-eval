#!/bin/sh

data_root="../data"
anchor_ip_path="../atlas-anchorIP-cont.txt"
probe_ip_path="../atlas-probeIP-cont.txt"
traceroute_methods="udp icmp tcp paris dublin"

# Make directory structure if it doesn't exist
if [ ! -d $data_root ]; then
    echo "Creating data directory structure at root: ${data_root}"
    mkdir $data_root
    for tr in $traceroute_methods; do
        mkdir "${data_root}/${tr}"
        mkdir "${data_root}/${tr}/traceroutes"
        mkdir "${data_root}/${tr}/pcaps"
    done
fi

# Run traceroutes
for ip_list in $anchor_ip_path $probe_ip_path; do
    # Log IP List information
    num_ips=$(wc -l "${ip_list}" | grep -o "^[0-9]*")
    echo "Using ${num_ips} IPs from IP List: ${ip_list}"
    # For each traceroute method
    for tr in $traceroute_methods; do
        echo "Running ${tr} traceroutes"
        # Specify output directories
        tr_dir="${data_root}/${tr}/traceroutes"
        pcap_dir="${data_root}/${tr}/pcaps"
        # For each IP
        while read -r ip; do
            tr_filepath="${tr_dir}/${tr}-${ip}.txt"
            pcap_filepath="${pcap_dir}/${tr}-${ip}.pcap"
            # Run tcpdump in the background
            sudo tcpdump port not 22 and port not 9100 and not arp -n -i enp1s0f1 -w "${pcap_filepath}" &
            # Run traceroute
            case $tr in
                icmp)
                    sudo traceroute ${ip} -I -n -m 64 > "${tr_filepath}"
                    ;;
                tcp)
                    sudo traceroute ${ip} -T -n -m 64 > "${tr_filepath}"
                    ;;
                udp)
                    sudo traceroute ${ip} -n -m 64 > "${tr_filepath}"
                    ;;
                paris)
                    sudo paris-traceroute -m64 -n ${ip} > "${tr_filepath}"
                    ;;
                dublin)
                    dublin-traceroute ${ip} --max-ttl=64 > "${tr_filepath}"
                    mv trace.json "${tr_dir}/${tr}-${ip}.json"
                    ;;
            esac
            # Kill tcpdump
            tcpdump_pid=$(ps -ef | pgrep -f "${pcap_filepath}" | grep -v grep)
            tcpdump_pid_clean=$(echo "$tcpdump_pid" | tr '\n' ' ')
            kill -2 $tcpdump_pid_clean
        done < "${ip_list}"
    done
done
