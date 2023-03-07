from os import listdir
from os.path import isdir, join
import json
import re
import pprint

data_root = "../data"
tr_methods = ["udp", "icmp", "tcp", "paris", "dublin"]

# JSON keys
TS = "Timestamp"
DEST = "DestinationIP"
TYPE = "TracerouteType"
HOPS = "Hops"
TTL = "TTL"
IP = "IPs"
RTT = "RTTs"

# Regex patterns
ip_pattern = re.compile(r"\d+\.\d+\.\d+\.\d+")
ping_pattern = re.compile(r"\d+\.\d+")

def base_parser(traceroute, method):
    """
    Parses one TCP, UDP, or, ICMP traceroute.

    Args: 
        traceroute (str): the full traceroute output
        method (str)    : the type of traceroute
    Returns:
        json_dict (dict): dict containing relevant information
    """
    lines = traceroute.split("\n")

    json_dict = {}
    json_dict[TS] = lines[0]
    json_dict[DEST] = lines[1].split()[2]
    json_dict[TYPE] = method
    json_dict[HOPS] = []

    # Each line represents one hop
    for hop in lines[2:-1]:
        tokens = hop.split()
        ttl = tokens[0]
        ips = []
        rtts = []
        
        # A token is either an IP, latency, "ms", or "*"
        for token in tokens[1:]:
            if token == "*":
                ips.append("*")
                rtts.append("*")
            elif ip_pattern.match(token):
                ips.append(token)
            elif ping_pattern.match(token):
                rtts.append(token)
                # If same IP reached
                if len(rtts) > len(ips):
                    # Find last non-"*" IP
                    last_ip = [ip for ip in ips if ip != "*"][-1]
                    ips.append(last_ip)
        
        # Add hop to data dictionary
        json_dict[HOPS].append({
            TTL: ttl, IP: ips, RTT: rtts
        })
    
    return json_dict

def tcp_parser(traceroute):
    """
    Parses one TCP traceroute.

    Args: 
        traceroute (str): the full traceroute output
    Returns:
        json_dict (dict): dict containing relevant information
    """
    return base_parser(traceroute, "tcp")

def udp_parser(traceroute):
    """
    Parses one UDP traceroute.

    Args: 
        traceroute (str): the full traceroute output
    Returns:
        json_dict (dict): dict containing relevant information
    """
    return base_parser(traceroute, "udp")

def icmp_parser(traceroute):
    """
    Parses one ICMP traceroute.

    Args: 
        traceroute (str): the full traceroute output
    Returns:
        json_dict (dict): dict containing relevant information
    """
    return base_parser(traceroute, "icmp")

def paris_parser(traceroute):
    """
    Parses one ICMP traceroute.

    Args: 
        traceroute (str): the full traceroute output
    Returns:
        json_dict (dict): dict containing relevant information
    """
    return base_parser(traceroute, "paris")

def dublin_parser(traceroute):
    """
    Parses one ICMP traceroute.

    Args: 
        traceroute (str): the full traceroute json as a string
    Returns:
        json_dict (dict): dict containing relevant information
    """
    flow_dicts = []
    traceroute = json.loads(traceroute)

    # JSON is a dict with flow_id keys
    for flow_id, flow in traceroute["flows"].items():
        json_dict = {}
        json_dict[TS] = flow[0]["sent"]["timestamp"]
        json_dict[DEST] = flow[0]["sent"]["ip"]["dst"]
        json_dict[TYPE] = "dublin"
        json_dict[HOPS] = []
        
        # The value of the flow_id is a list of hop dictionaries
        for hop in flow:
            ttl = hop["sent"]["ip"]["ttl"]
            try:
                rtt = hop["rtt_usec"]/1000
                ip = hop["received"]["ip"]["src"]
            except TypeError:
                rtt = "*"
                ip = "*"

             # Add hop to data dictionary
            json_dict[HOPS].append({
                TTL: ttl, IP: [ip if ip else "*"], RTT: [rtt if rtt else "*"]
            })
            
        flow_dicts.append(json_dict)

    return flow_dicts

parsers = {"udp": udp_parser, "icmp": icmp_parser, "tcp": tcp_parser, "paris": paris_parser, "dublin": dublin_parser}

if __name__ == "__main__":

    # Check data directories exist
    assert isdir(data_root), f"Root {data_root} does not exist."
    for tr in tr_methods:
        assert isdir(join(data_root, tr)), f"Data directory {tr} does not exist."
    
    # Load data (filenames)
    print("Checking for data...")
    filenames = {}
    for tr in tr_methods:
        filenames[tr] = listdir(join(data_root, tr, "traceroutes"))
        print(f"\tFound {len(filenames[tr])} {tr} traceroutes.")

    # Parse data
    print("Parsing data...")
    for tr in tr_methods:
        src_dir = join(data_root, tr, "traceroutes")

    # with open("../sample-traceroutes/trace.json") as f:
    #     traceroute = f.read()
    #     json_dicts = dublin_parser(traceroute)
    #     pprint.pprint(json_dicts[0])

    