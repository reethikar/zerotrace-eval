package main

import (
	"errors"
	"regexp"
	"golang.org/x/exp/slices"
	"sort"
	"time"
	"log"
	"github.com/google/uuid"

)

var (
	invalidInputErr = errors.New("Invalid Input")
)

type FormDetails struct {
	UUID         string
	Timestamp    string
	Contact      string
	ExpType      string
	Device       string
	Network	     string
	Browser      string
	LocationVPN  string
	LocationUser string
}

type AppRTTStats struct {
	MinRTT float64
	MaxRTT float64
	MeanRTT float64
	MedianRTT float64
}

type PingMsmt struct {
	IP        string
	PktSent   int
	PktRecv   int
	PktLoss   float64
	MinRtt    float64
	AvgRtt    float64
	MaxRtt    float64
	StdDevRtt float64
}


type Results struct {
	UUID		string
	IPaddr		string
	Timestamp	string
	MSSVal		uint32
	AllAppLayerRtt	AppRTTStats
	AppLayerRtt	float64
	ICMPRtt		PingMsmt
	NWLayerRttTCP	float64
	NWLayerRttICMP	float64
	NWLayerRtt0T	float64
	RTTDiff		float64
}

// validateForm validates user input obtained from /measure webpage
func validateForm(email string, expType string, device string, network string, browser string, locationVPN string, locationUser string) (*FormDetails, error) {
	log.Println("here")
	if match, _ := regexp.MatchString(`^\w+$`, email); !match {
		return nil, invalidInputErr
	}
	if expType != "vpn" && expType != "direct" {
		return nil, invalidInputErr
	}
	if device != "mobile" && device != "desktop" {
		return nil, invalidInputErr
	}
	expectedBrowsers := []string{"chrome", "brave", "safari", "firefox", "edge", "opera"}
	if !slices.Contains(expectedBrowsers, browser) {
		return nil, invalidInputErr
	}
	if match, _ := regexp.MatchString(`^[a-zA-Z0-9_ ]+$`, network); !match  {
		return nil, invalidInputErr
        }
	if match, _ := regexp.MatchString(`^[\w,.'";:\s\d(){}]*$`, locationVPN); !match {
		return nil, invalidInputErr
	}
	if match, _ := regexp.MatchString(`^[\w,.'";:\s\d(){}]*$`, locationUser); !match {
		return nil, invalidInputErr
	}
	details := FormDetails{
		UUID:         uuid.NewString(),
		Timestamp:    time.Now().UTC().Format("2006-01-02T15:04:05.000000"),
		Contact:      email,
		ExpType:      expType,
		Device:       device,
		Network:      network,
		Browser:      browser,
		LocationVPN:  locationVPN,
		LocationUser: locationUser,
	}
	return &details, nil
}

// isValidUUID checks if UUID u is valid
func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}

func fmtTimeMs(value time.Duration) float64 {
	return (float64(value) / float64(time.Millisecond))
}

func mean(ms []time.Duration) time.Duration {
	var t time.Duration

	for _, m := range ms {
		t += m
	}

	return t / time.Duration(len(ms))
}

func median(ms []time.Duration) time.Duration {
	if len(ms)%2 == 1 {
		return ms[len(ms)/2+1]
	}
	a := ms[len(ms)/2-1]
	b := ms[len(ms)/2]
	return a + b/2
}

func calcStats(ms []time.Duration) AppRTTStats {
	less := func(i, j int) bool {
		return ms[i] < ms[j]
	}
	sort.Slice(ms, less)

        allAppRTT := AppRTTStats{
		MinRTT: fmtTimeMs(ms[0]),
		MaxRTT: fmtTimeMs(ms[len(ms)-1]),
		MeanRTT: fmtTimeMs(mean(ms)),
		MedianRTT: fmtTimeMs(median(ms)),
	}
	return allAppRTT
}

