package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/brave/zerotrace"
	"github.com/go-chi/chi"
	"github.com/go-ping/ping"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
)

var (
	icmpCount	 = 5
	icmpTimeout	 = time.Second * 10
	iface            string
	InfoLogger       *log.Logger
	directoryPath    = ""
	numAppLayerPings = 100
	connStates       = &stateMachine{m: make(map[fourTuple]*handshake)}
	l                = log.New(os.Stderr, "example: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

// getMinRttValue gets the minimum non-zero and non-negative RTT value from the array
func getMinRttValue(nwLayerRtt []float64) float64 {
	minimum := math.MaxFloat64
	for _, v := range nwLayerRtt {
		if v < minimum && v > 0 {
			minimum = v
		}
	}
	if minimum == math.MaxFloat64 {
		return float64(0)
	}
	return minimum
}

// icmpPinger sends ICMP pings and returns statistics
func icmpPinger(ip string) (*PingMsmt, error) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return nil, err
	}
	pinger.Count = icmpCount
	pinger.Timeout = icmpTimeout
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		return nil, err
	}
	stat := pinger.Statistics()
	pingMsmt := PingMsmt{ip, stat.PacketsSent, stat.PacketsRecv, stat.PacketLoss, fmtTimeUs(stat.MinRtt), fmtTimeUs(stat.AvgRtt), fmtTimeUs(stat.MaxRtt), fmtTimeUs(stat.StdDevRtt), fmtTimeUsArray(stat.Rtts)}
	return &pingMsmt, nil
}

func webSocketHandler(w http.ResponseWriter, r *http.Request) {
	var ms []time.Duration
	var nwLayerRttTCP, nwLayerRttICMP, nwLayerRtt0T float64
	var mssVal uint32
	var uuid string
	var fourTuple *fourTuple

	for k, v := range r.URL.Query() {
		if k == "uuid" && isValidUUID(v[0]) {
			uuid = v[0]
		} else {
			http.Error(w, "Invalid UUID", http.StatusInternalServerError)
			return
		}
	}

	clientIPstr := r.RemoteAddr
	clientIP, _, _ := net.SplitHostPort(clientIPstr)

	// Upgrade the connection to WebSocket.
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()

	// At this point, the TCP handshake of the WebSocket connection
	// completed and we can query our state machine to learn the
	// network-layer RTT.
	fourTuple, err = connToFourTuple(c.UnderlyingConn())
	// RTT returns -1 if method was unsuccessful
	nwLayerRttTCP = -1
	if err != nil {
		l.Printf("Failed to get four-tuple from WebSocket connection: %v", err)
	} else {
		tcpRtt, err := connStates.rttByTuple(fourTuple)
		if err != nil {
			l.Printf("Failed to get TCP RTT for WebSocket four-tuple: %v", err)
		} else {
			nwLayerRttTCP = fmtTimeUs(tcpRtt)
			l.Printf("RTT of WebSocket's TCP handshake: %v", tcpRtt)
		}
		mss, err := connStates.mssByTuple(fourTuple)
		if err != nil {
			l.Printf("Failed to get TCP MSS for WebSocket four-tuple: %v", err)
		} else {
			mssVal = mss
			l.Printf("MSS of WebSocket's TCP handshake: %v", mss)
		}
	}

	// Use the WebSocket connection to send application-layer pings to the
	// client and determine the round trip time.
	for i := 0; i < numAppLayerPings; i++ {
		then := time.Now().UTC()
		err = c.WriteMessage(websocket.TextMessage, []byte(then.String()))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _, err := c.ReadMessage()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		now := time.Now().UTC()
		ms = append(ms, now.Sub(then))
		time.Sleep(time.Millisecond * 200)
	}

	var appLayerRtt = calcStats(ms)

	done := make(chan bool)
	// Start 0trace measurement in the background.
	go func() {
		// Now, run a 0trace measurement (using the underlying WebSocket
		// connection) to determine the network-layer round trip time.  Note
		// that this may corrupt the open WebSocket connection but we're
		// fine with that because we already have the application-layer round
		// trip time.
		wssConn := c.UnderlyingConn()
		cfg := zerotrace.NewDefaultConfig()
		cfg.Interface = iface
		z := zerotrace.NewZeroTrace(cfg)
		nwLayer0TResults, err := z.CalcStat(wssConn)
		if err != nil {
			l.Println("Error determining RTT with zerotrace", err)
		}
		nwLayerRtt0T = fmtTimeUs(nwLayer0TResults.RTT)
		l.Printf("0trace network-layer RTT: %s", nwLayer0TResults.RTT)
		// Run ICMP measurement towards the clientIP on network layer
		icmpResults, err := icmpPinger(clientIP)
		if err != nil {
			l.Println("ICMP Ping Error: ", err)
		}
		nwLayerRttICMP = icmpResults.MinRtt

		nwLayerRtt := []float64{nwLayerRttTCP, nwLayerRttICMP, nwLayerRtt0T}
		rttDiff := appLayerRtt.MinRtt - getMinRttValue(nwLayerRtt)
		// Combine all results
		results := Results{
			UUID:			uuid,
			IPaddr:			clientIP,
			//RFC3339 style UTC date time with added seconds information
			Timestamp:		time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
			MSSVal:			mssVal,
			AllAppLayerRtt: 	appLayerRtt,
			AppLayerRtt:    	appLayerRtt.MinRtt,
			ICMPRtt:		*icmpResults,
			FourTuple:		*fourTuple,
			ZeroTraceResults:	nwLayer0TResults,
			NWLayerRttTCP:		nwLayerRttTCP,
			NWLayerRttICMP:		nwLayerRttICMP,
			NWLayerRtt0T:		nwLayerRtt0T,
			RttDiff:        	rttDiff,
		}
		resultsjsObj, err := json.Marshal(results)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resultString := string(resultsjsObj)

		InfoLogger.Println(resultString)
		close(done)
	}()

	// Keep the client around while the measurement is running because we need
	// to take advantage of the already-established TCP connection.
	for {
		select {
		case <-done:
			l.Println("0trace measurement is done.")
			return
		case <-time.Tick(time.Second):
			if err := c.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				l.Printf("Error writing message to WebSocket conn: %v", err)
			}
		}
	}
}

func indexHandler(domain string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var uuid string
		for k, v := range r.URL.Query() {
			if k == "uuid" && isValidUUID(v[0]) {
				uuid = v[0]
			} else {
				http.Error(w, "Invalid UUID", http.StatusInternalServerError)
				return
			}
		}
		endpoint := fmt.Sprintf("wss://%s/websocket?uuid=%s", domain, uuid)
		buf := new(bytes.Buffer)
		var latencyTemplate, _ = template.ParseFiles(path.Join(directoryPath, "templates/latency.html"))
		if err := latencyTemplate.Execute(buf, struct {
			WebSocketEndpoint string
		}{
			endpoint,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, string(buf.String()))
	}
}

// measureHandler serves the form which collects user's contact data and ground-truth (VPN/Direct) before experiment begins
func measureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		serveFormTemplate(w)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		details, err := validateForm(r.FormValue("email"), r.FormValue("exp_type"), r.FormValue("device"), r.FormValue("network"), r.FormValue("browser"), r.FormValue("name_vpn"), r.FormValue("location_vpn"), r.FormValue("location_user"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsObj, err := json.Marshal(details)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resultString := string(jsObj)
		InfoLogger.Println(resultString)
		http.Redirect(w, r, "/ping?uuid="+details.UUID, 302)
	}
}

// serveFormTemplate serves the form
func serveFormTemplate(w http.ResponseWriter) {
	var WebTemplate, _ = template.ParseFiles(path.Join(directoryPath, "templates/measure.html"))
	if err := WebTemplate.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	var logfilePath, addr, domain string
	flag.StringVar(&iface, "iface", "enp1s0f1", "Network interface name to listen on (default: enp1s0f1)")
	flag.StringVar(&addr, "addr", ":443", "Address to listen on (default: :443)")
	flag.StringVar(&domain, "domain", "test.reethika.info", "The Web server's domain name.")
	flag.StringVar(&logfilePath, "logfile", "logFile.jsonl", "Path to log file")
	flag.Parse()

	l.Println("Starting packet capture goroutine.")
	go capture(connStates, iface)

	file, err := os.OpenFile(logfilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}

	if domain == "" {
		l.Fatal("Specify domain name by using the -domain flag.")
	}
	InfoLogger = log.New(file, "", 0)
	router := chi.NewRouter()
	router.Get("/websocket", webSocketHandler)
	router.Get("/ping", indexHandler(domain))
	router.Get("/measure", measureHandler)
	router.Post("/measure", measureHandler)
	// Serve images and css from static folder
	router.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("certs"),
		HostPolicy: autocert.HostWhitelist(domain),
	}
	
	go http.ListenAndServe(":http", certManager.HTTPHandler(nil)) //nolint:errcheck
	server := &http.Server{
		Addr:    addr,
		Handler: router,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	l.Printf("Starting Web service to listen on %s.", addr)
	l.Println(server.ListenAndServeTLS("", ""))
}
