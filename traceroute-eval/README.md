# Evaluating Traceroute Methods against the ZeroTrace Implementation
/scripts will contain will the parsing scripts and the scripts to trigger the tcpdump and traceroute code

- `traceroute.sh` - Set the `ip_list` variable to the path to your IP List. Run it as `sudo ./traceroute.sh`
- `parse-traceroutes.py`- Assumes the same data directory structure as `traceroute.sh` so I would not change the `data_root` or anything else to do with that. Run this as `python3 parse-traceroutes.py`.
