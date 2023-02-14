require 'json'

ip = File.open('logFile.jsonl','r')
url = ARGV[0]
url_parts = url.strip.split("?uuid=")
uuid = url_parts[-1]
ip.each_line do |line|
	json = JSON.parse(line.strip)
	next if json["UUID"] != uuid
	if json["Contact"] != nil 
		puts "Timestamp: 			" + json["Timestamp"]
		puts "Experiment Conductor: 		" + json["Contact"]
		puts "Experiment Type:		" + json["ExpType"]
		puts "Experiemnt Device: 		" + json["Device"]
		if json["ExpType"] == "vpn"
			puts "Location of VPN: 			" + json["LocationVPN"]
			puts "Location of User:			" + json["LocationUser"]
		end
	else
		puts "AllAppLayerRtt: 		" + json["AllAppLayerRtt"].to_s
		puts "AppLayerRtt (Minimum) 		" + json["AppLayerRtt"].to_s
		puts "Network Layer Rtt: 		" + json["NWLayerRtt"].to_s
		puts "RTT Diff: 			" + json["RTTDiff"].to_s
	end

end
