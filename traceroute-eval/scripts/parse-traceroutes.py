from os import listdir
from os.path import isdir, join
from ipaddress import IPv4Address, AddressValueError
import json
import re

data_root = "../../../../../scratch/traceroute-data-1679617006"
tr_methods = ["udp", "icmp", "tcp", "paris", "dublin"]
output_file = "parse-traceroutes-output.json"

# JSON keys
TS = "Timestamp"
DEST = "DestinationIP"
TYPE = "TracerouteType"
HOPS = "Hops"
TTL = "TTL"
IP = "HopIPs"
RTT = "RTTs"

# Helpers

def is_ip(token):
    """
    Tries to parse token as an IPv4 address to determine if it's an IP
    
    Args: 
        token (str)     : single token from single traceroute line
    Returns:
        result (bool)   : whether the token is an IP
    """
    try:
        IPv4Address(token)
        return True
    except AddressValueError:
        return False

def is_ping(token):
    """
    Tries to parse token as a latency
    
    Args: 
        token (str)     : single token from single traceroute line
    Returns:
        result (bool)   : whether the token is a latency
    """
    ping_pattern = re.compile(r"\d+\.\d+")
    return ping_pattern.match(token)


# Parsers

def base_parser(traceroute, method):
    """
    Parses one TCP, UDP, or, ICMP traceroute.

    Args: 
        traceroute (str): the full traceroute output
        method (str)    : the type of traceroute
    Returns:
        json_dict (dict): dict containing relevant information
    """

    lines = traceroute.rstrip("\n").split("\n")

    json_dict = {
        TS: lines[0],
        DEST: lines[1].split()[2],
        TYPE: method,
        HOPS: []
    }
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
            elif is_ip(token):
                ips.append(token)
            elif is_ping(token):
                rtts.append(token)
                # If this rtt corresponds with an IP we've seen
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
        json_dict = {
            TS: flow[0]["sent"]["timestamp"],
            DEST: flow[0]["sent"]["ip"]["dst"],
            TYPE: "dublin",
            "FlowID": flow_id,
            HOPS: []
        }
        # The corresponding value is a list of hop dictionaries
        for hop in flow:
             # Add hop to data dictionary
            json_dict[HOPS].append({
                TTL: hop["sent"]["ip"]["ttl"], 
                IP: [hop["received"]["ip"]["src"] if hop["rtt_usec"] else "*"], 
                RTT: [hop["rtt_usec"]/1000 if hop["rtt_usec"] else "*"]
            })
            
        flow_dicts.append(json_dict)

    return flow_dicts

if __name__ == "__main__":

    # Check data directories exist
    assert isdir(data_root), f"Root {data_root} does not exist."
    for tr in tr_methods:
        assert isdir(join(data_root, tr)), f"Data directory {tr} does not exist."
    
    # Load data (filenames)
    print("Checking for data...")
    filenames = {}
    for tr in tr_methods:
        filenames[tr] = listdir(join(data_root, tr))
        print(f"\tfound {len(filenames[tr])} {tr} traceroutes")

    # Parse data
    print("Parsing data...")
    json_dict = {}

    for tr in tr_methods:
        print(f"\tparsing {tr}...")
        src_dir = join(data_root, tr)
        files = filenames[tr]
        json_dict[tr] = []

        for file in files:
            with open(join(src_dir, file)) as f:
                contents = f.read()
                if tr == "udp":
                    parsed = udp_parser(contents)
                elif tr == "icmp":
                    parsed = icmp_parser(contents)
                elif tr == "tcp":
                    parsed = tcp_parser(contents)
                elif tr == "paris":
                    parsed = paris_parser(contents)
                elif tr == "dublin": 
                    try:
                        parsed = dublin_parser(contents)
                    except TypeError:
                        print(file)
                else:
                    print(f"Unknown traceroute method: {tr}")
                
                if type(parsed) is dict:
                    json_dict[tr].append(parsed)
                else:
                    json_dict[tr].extend(parsed)

    # Save to JSON file
    print(f"Saving output to {output_file}")
    with open("parse-traceroutes-output.json", "w") as f:
        json.dump(json_dict, f, indent=4)
        print("\tdone")
