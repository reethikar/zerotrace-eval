package main

import (
	"crypto/tls"
	"flag"
	"html/template"
	"encoding/json"
	"bytes"
	"net"
	"fmt"
	"math"
	"path"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/brave/zerotrace"
	"github.com/go-chi/chi"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
)

var (
	InfoLogger    *log.Logger
	directoryPath = ""
	numAppLayerPings = 100
	l = log.New(os.Stderr, "example: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

func webSocketHandler(w http.ResponseWriter, r *http.Request) {
	var ms []time.Duration

	var uuid string
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
		z := zerotrace.NewZeroTrace(zerotrace.NewDefaultConfig())
		var nwLayerRtt time.Duration
		nwLayerRtt, err = z.CalcRTT(wssConn)
		if err != nil {
			l.Println("Error determining RTT with zerotrace", err)
		}

		rttDiff := fmtTimeMs(appLayerRtt.MinRTT) - fmtTimeMs(nwLayerRtt)
		rttDiff = math.Abs(rttDiff)

		// Combine all results
		results := Results{
			UUID:   uuid,
			IPaddr: clientIP,
			//RFC3339 style UTC date time with added seconds information
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
			AllAppLayerRtt: appLayerRtt,
			AppLayerRtt: fmtTimeMs(appLayerRtt.MinRTT),
			NWLayerRtt: fmtTimeMs(nwLayerRtt),
			RTTDiff: rttDiff,
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

func indexHandler(w http.ResponseWriter, r *http.Request) {
	var uuid string
	for k, v := range r.URL.Query() {
		if k == "uuid" && isValidUUID(v[0]) {
			uuid = v[0]
		} else {
			http.Error(w, "Invalid UUID", http.StatusInternalServerError)
			return
		}
	}
	endpoint := "wss://localhost/websocket?uuid="+uuid
	buf := new(bytes.Buffer)
	var latencyTemplate, _ = template.ParseFiles(path.Join(directoryPath, "latency.html"))
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

// measureHandler serves the form which collects user's contact data and ground-truth (VPN/Direct) before experiment begins
func measureHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		serveFormTemplate(w)
	} else {
		if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
		}
		details, err := validateForm(r.FormValue("email"), r.FormValue("exp_type"), r.FormValue("device"), r.FormValue("network"), r.FormValue("browser"),  r.FormValue("location_vpn"), r.FormValue("location_user"))
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
	var WebTemplate, _ = template.ParseFiles(path.Join(directoryPath, "measure.html"))
	if err := WebTemplate.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	var logfilePath, addr, domain, ifaceName string
	flag.StringVar(&ifaceName, "iface", "enp1s0f1", "Network interface name to listen on (default: eth0)")
	flag.StringVar(&addr, "addr", ":443", "Address to listen on (default: :443)")
	flag.StringVar(&domain, "domain", "localhost", "The Web server's domain name.")
	flag.StringVar(&logfilePath, "logfile", "logFile.jsonl", "Path to log file")
	flag.Parse()

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
	router.Get("/ping", indexHandler)
	router.Get("/measure", measureHandler)
	router.Post("/measure",measureHandler)

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
