# Run this like: ruby analysis.rb logFile.jsonl rttdiff.jsonl          
require 'set'
require 'json'
require 'HTTParty'

Results = Struct.new(:uuid, :ipaddr, :mss, :websocketRTT, :tcpRTT, :icmpRTT, :ztRTT, :ztLH)
Diff = Struct.new(:uuid, :exptype, :mss, :type, :rttd)
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
    # is websocket (applayer) and tcp handshake ~equal? 
    #yes: nw layer proxy or direct
    #no: maybe app layer proxy
    if tcpRTT != -1 && getDiffinMs(websocketRTT, tcpRTT) < AlmostEqualVal 
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
        if icmpRTT != 0 && tcpRTT != -1 && getDiffinMs(tcpRTT, icmpRTT) < AlmostEqualVal
            # branch 2a
            type = "E2EWsTCPICMP"
            diff = getDiffinMs(websocketRTT, [tcpRTT, icmpRTT].min)
        else
            #branch 2b 
            type = "E2EWsICMP"
            diff = getDiffinMs(websocketRTT, icmpRTT)
        end
    end
    return type, diff
end

metaType = Hash.new
count = 0
#reethika@Reethikas-MBP-16 generate graph % grep "riyaag" LATEST-w41-logFile.jsonl| grep "direct" | jq '.UUID'
# https://umsec.slack.com/archives/C04MGH6TSMS/p1680011434405349
#remove the corrupted direct ones and uuid with only one entry in logfile
corruptedUUIDs = [
"22e22f60-6a61-4a54-ac28-f2821d546a89",
"7feecb17-5c76-4817-a816-de7782b368ea",
"96a87f53-9ae5-419f-b347-5069cf05ce8c",
"214d7483-28c2-4c23-8232-69a043516d71",
"f78d4a1d-7ced-4be4-8ed4-b2506cf8fcad",
"0ff8b5fd-b087-4c99-8685-b1d770265f6e",
"26227f0e-c470-4d1a-95c1-ef63bf303d88",
"5e8806c8-cd27-4ec2-83d8-7aa291e2258f",
"cd9d4657-37a9-4244-ade6-e0c46478eda8",
"1eaf63c1-fa08-4866-9261-f29463aca984",
"9b41b1ca-3ac1-4238-bab3-8110b9f01cc8",
"33bf7729-9dc9-4d00-902d-34b623f85023",
"b6bffca9-8b3e-4a73-b745-dddc9dbc4e88",
"61a502d5-adc2-490d-892e-930515d03166",
"fef78435-faa8-4f4a-afc4-67903a53fc32",
"f0a9a694-d4f9-4f87-b070-e337cb2a5355",
"ceaca126-af9d-4c99-8529-2825cd831a8c",
"cdbfd623-133d-400c-a0b8-4d28a6c2ccf0",
"b2903edc-110b-465b-b191-2ac9e90022d0",
"b265b518-fea6-4d23-bae7-01ace3d02436",
"aa7a7145-e4dd-4116-84f7-693212bc8cec",
"a92c6258-57a2-4658-bcf5-f8ca32a9d51e",
"a2a85861-78ff-4e5a-8b33-00e52706dd11",
"954a6fd0-2e91-425f-9abd-9c732f476314",
"87602124-0b11-471e-ad7f-3fec20a96f91",
"7690fbbd-95c5-4b27-bc91-23d6ad2967bd",
"6c1759b1-77c0-404f-a00c-ecc35fa5fd2d",
"5b2b0c00-81b1-44c3-9564-f1c3c67b5f7b",
"3780bbfc-a0c3-4279-a478-3acd0136cf38",
"302c73f6-f9e1-453b-a0d3-edf55c06b453",
"0efb8810-8733-426e-aad2-69513e74c7b8",
"0708a118-50b3-40a3-a6bb-9158df48b0fb",
"04175c23-1f93-47d0-9369-0f7dcb376423",
]

logfile.each_line do |line|
    json = JSON.parse(line.strip)
    uuid = json["UUID"]
    next if corruptedUUIDs.include?(uuid)
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
    item = Diff.new(uuid, metaType[uuid], mss, type, rttd)
    rttDiff << item
end

puts "-1 TCP RTT: " + count.to_s

sorteditems = rttDiff.sort {| a, b | a[:rttd] <=> b[:rttd] }

sorteditems.each do |item|
    op.puts JSON.dump(item.to_h)
end