package main

import (
	"errors"
	"regexp"
	"golang.org/x/exp/slices"
	"sort"
	"time"
	"net/mail"
	"github.com/google/uuid"
	"github.com/brave/zerotrace"
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
	VPNprovider  string
	LocationVPN  string
	LocationUser string
}

type AppRttStats struct {
	MinRtt float64
	MaxRtt float64
	MeanRtt float64
	MedianRtt float64
	AllRtt	[]float64
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
	AllRtt	  []float64
}


type Results struct {
	UUID		string
	IPaddr		string
	Timestamp	string
	MSSVal		uint32
	AllAppLayerRtt	AppRttStats
	AppLayerRtt	float64
	ICMPRtt		PingMsmt
	FourTuple	fourTuple
	ZeroTraceResults zerotrace.ZeroTraceResult
	NWLayerRttTCP	float64
	NWLayerRttICMP	float64
	NWLayerRtt0T	float64
	RttDiff		float64
}

// validateForm validates user input obtained from /measure webpage
func validateForm(email string, expType string, device string, network string, browser string, nameVPN string, locationVPN string, locationUser string) (*FormDetails, error) {
	if _, err := mail.ParseAddress(email); err != nil {
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
	if match, _ := regexp.MatchString(`^[\w,.'";:\-\s\d(){}]*$`, nameVPN); !match {
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
		VPNprovider:  nameVPN,
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

func fmtTimeUs(value time.Duration) float64 {
	return (float64(value) / float64(time.Microsecond))
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

func fmtTimeUsArray(ms []time.Duration) []float64 {
	var allRtt []float64
	for _, v := range ms {
		allRtt = append(allRtt, fmtTimeUs(v))
	}
	return allRtt
}

func calcStats(ms []time.Duration) AppRttStats {
	less := func(i, j int) bool {
		return ms[i] < ms[j]
	}
	sort.Slice(ms, less)

        allAppRtt := AppRttStats{
		MinRtt: fmtTimeUs(ms[0]),
		MaxRtt: fmtTimeUs(ms[len(ms)-1]),
		MeanRtt: fmtTimeUs(mean(ms)),
		MedianRtt: fmtTimeUs(median(ms)),
		AllRtt: fmtTimeUsArray(ms),
	}
	return allAppRtt
}

