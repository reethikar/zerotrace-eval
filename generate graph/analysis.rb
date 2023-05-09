# Clean the logFile before running this analysis.rb
# Run this like: ruby analysis.rb clean-w41-logFile.jsonl rttdiff.jsonl          
require 'set'
require 'json'
require 'HTTParty'

Results = Struct.new(:uuid, :ipaddr, :mss, :websocketRTT, :tcpRTT, :icmpRTT, :ztRTT, :ztLH)
Diff = Struct.new(:uuid, :ipaddr, :exptype, :mss, :type, :rttd)
results = Array.new
rttDiff = Array.new
logfile = File.open(ARGV[0],'r')
op = File.open(ARGV[1], 'w')
# 30 ms is a number that comes from RIPE atlas experiments
# over 90% of the RIPE Atlas measurements had an RTT difference less than 30ms
AlmostEqualVal = 30

def getDiffinMs(a,b)
    return ((a-b).abs)/1000.0
end

def lookupASNs(ipaddr)
    url = "https://stat.ripe.net/data/network-info/data.json?resource=" + ipaddr
    response = HTTParty.get(url)
    jsonr = JSON.parse(response.body)
    asns = jsonr["data"]["asns"]
    return asns
end

def determineRttDiff(curr)
    ipaddr = curr.ipaddr
    mss = curr.mss
    websocketRTT = curr.websocketRTT
    tcpRTT = curr.tcpRTT
    icmpRTT = curr.icmpRTT
    ztRTT = curr.ztRTT
    ztLH = curr.ztLH
    type = ""
    diff = nil
    # is websocket (applayer) and tcp handshake ~equal? or is tcp higher than websocket 
    #yes: nw layer proxy or direct
    #no: maybe app layer proxy
    if tcpRTT != -1 
        if (getDiffinMs(websocketRTT, tcpRTT) < AlmostEqualVal || tcpRTT > websocketRTT)
            # branch 1
            if icmpRTT != 0
                # branch 3
                type = "WsICMP"
                diff = getDiffinMs(websocketRTT, icmpRTT)
            else
                # branch 4
                if ztLH == ipaddr
                    # branch 5
                    type = "Ws0TClient"
                    diff = getDiffinMs(websocketRTT, ztRTT)
                else
                    # branch 6
                    clientAS = lookupASNs(ipaddr)
                    if ztLH != nil
                        ztAS = lookupASNs(ztLH) 
                    else
                        ztAS = []
                    end          
                    intersectionAS = clientAS & ztAS
                    if intersectionAS.length > 0
                        # branch 7
                        type = "Ws0TNetwork"
                        diff = getDiffinMs(websocketRTT, ztRTT)
                    else 
                        #branch 8
                        if mss < 1460
                            # branch 9
                            type = "BestEffortWs0T"
                            diff = getDiffinMs(websocketRTT, ztRTT)
                        else
                            # branch 10
                            type = "ProbablyDirect/InsufficientDataforVPN"
                            diff = getDiffinMs(websocketRTT, ztRTT)
                        end
                    end
                end
            end
        else
            # branch 2
            if icmpRTT != 0 && getDiffinMs(tcpRTT, icmpRTT) < AlmostEqualVal
                # branch 2a
                type = "E2EWsTCPICMP"
                diff = getDiffinMs(websocketRTT, [tcpRTT, icmpRTT].min)
            else 
                if getDiffinMs(tcpRTT, ztRTT) < AlmostEqualVal
                    type = "E2EWsTCP0T"
                    diff = getDiffinMs(websocketRTT, [tcpRTT, ztRTT].min)  
                else
                    if icmpRTT != 0 
                        type = "E2EWsICMP"
                        diff = getDiffinMs(websocketRTT, icmpRTT)
                    else
                        clientAS = lookupASNs(ipaddr)
                        if ztLH != nil
                            ztAS = lookupASNs(ztLH) 
                        else
                            ztAS = []
                        end 
                        intersectionAS = clientAS & ztAS
                        if intersectionAS.length > 0
                            type = "E2EWs0TNetwork"
                            diff = getDiffinMs(websocketRTT, ztRTT)
                        else
                            type = "E2EBestEffortWsTCP"
                            diff = getDiffinMs(websocketRTT, tcpRTT)
                        end
                    end
                end
            end 
        end
    end
    return type, diff
end

metaType = Hash.new
count = 0

logfile.each_line do |line|
    json = JSON.parse(line.strip)
    uuid = json["UUID"]
    if json["ExpType"] != nil
        metaType[uuid] = json["ExpType"]
    end
    ipaddr = json["IPaddr"]
    next if ipaddr == nil
    mss = json["MSSVal"]
    websocketRTT = json["AppLayerRtt"] # microseconds
    tcpRTT = json["NWLayerRttTCP"] #microseconds
    if tcpRTT == -1
        count +=1
    end
    icmpRTT = json["NWLayerRttICMP"] # microseconds
    ztRTT = json["NWLayerRtt0T"] # microseconds
    # if it exists
    if json["ZeroTraceResults"] != nil
        ztLH = json["ZeroTraceResults"]["ClosestPktIP"]
    end
    curr = Results.new(uuid, ipaddr, mss, websocketRTT, tcpRTT, icmpRTT, ztRTT, ztLH)
    results << curr
    type, rttd = determineRttDiff(curr)
    item = Diff.new(uuid, ipaddr, metaType[uuid], mss, type, rttd)
    rttDiff << item
end

puts "-1 TCP RTT: " + count.to_s

sorteditems = rttDiff.sort {| a, b | a[:rttd] <=> b[:rttd] }

sorteditems.each do |item|
    op.puts JSON.dump(item.to_h)
end