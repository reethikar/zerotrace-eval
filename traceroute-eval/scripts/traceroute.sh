#!/bin/sh

data_root="../data-1:5"
ip_list="../atlas-probeIP-5.txt"
traceroute_methods="udp icmp tcp paris"

# Make directory structure if it doesn't exist
if [ ! -d $data_root ]; then
    echo "Creating data directory structure at root: ${data_root}"
    mkdir $data_root
    mkdir "${data_root}/pcaps"
    for tr in $traceroute_methods; do
        mkdir "${data_root}/${tr}"
    done
    mkdir "${data_root}/dublin"
fi

# Log IP List information
num_ips=$(wc -l "${ip_list}" | grep -o "^[0-9]*")
echo "Using ${num_ips} IPs from IP List: ${ip_list}"

pcap_dir="${data_root}/pcaps"
udp_tr_dir="${data_root}/udp"
icmp_tr_dir="${data_root}/icmp"
tcp_tr_dir="${data_root}/tcp"
paris_tr_dir="${data_root}/paris"
dublin_tr_dir="${data_root}/dublin"

# Run all traceroutes together
while read -r ip; do
    echo -n "${ip}...\r"
    icmp_tr_file="${icmp_tr_dir}/icmp-${ip}.txt"
    tcp_tr_file="${tcp_tr_dir}/tcp-${ip}.txt"
    udp_tr_file="${udp_tr_dir}/udp-${ip}.txt"
    paris_tr_file="${paris_tr_dir}/paris-${ip}.txt"
    dublin_tr_file="${dublin_tr_dir}/dublin-${ip}.txt"
    pcap_filepath="${pcap_dir}/${ip}.pcap"
    date +%s | tee "${icmp_tr_file}" "${tcp_tr_file}" "${udp_tr_file}" "${paris_tr_file}" "${dublin_tr_file}" > /dev/null
    pids=""
    # Run tcpdump in the background and then run icmp, udp, tcp, and paris traceroutes parallelly
    sudo tcpdump port not 22 and port not 9100 and not arp -n -i enp1s0f1 -w "${pcap_filepath}" 2> /dev/null &
    (for tr in $traceroute_methods; do 
        case $tr in
            icmp)
                sudo traceroute "${ip}" -I -n -m 64 >> "${icmp_tr_file}" & 
                ;;
            tcp)
                sudo traceroute "${ip}" -T -n -m 64 >> "${tcp_tr_file}" & 
                ;;
            udp)
                sudo traceroute "${ip}" -n -m 64 >> "${udp_tr_file}" & 
                ;;
            paris)
                sudo paris-traceroute -m64 -n "${ip}" >> "${paris_tr_file}" & 
                ;;
        esac
    done; wait) & all_tr=$!
    # Wait for these traceroute subprocesses to finish (and do not wait for tcpdump as that does not signal DONE unless we interrupt it)
    wait $all_tr
    dublin-traceroute "${ip}" --max-ttl=64 --npaths=3 > /dev/null
    mv trace.json "${dublin_tr_file}"

    # Kill tcpdump for the particular IP
    tcpdump_pid=$(ps -ef | pgrep -f "${pcap_filepath}" | grep -v grep)
    tcpdump_pid_clean=$(echo "$tcpdump_pid" | tr '\n' ' ' | xargs)
    kill -9 $tcpdump_pid_clean
done < "${ip_list}"

echo "Finished          "