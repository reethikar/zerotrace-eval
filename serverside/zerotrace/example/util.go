package main

import (
	"fmt"
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
	MinRTT time.Duration
	MaxRTT time.Duration
	MeanRTT time.Duration
	MedianRTT time.Duration
}

type Results struct {
	UUID       string
	IPaddr     string
	Timestamp  string
	AllAppLayerRtt AppRTTStats
	AppLayerRtt float64
	NWLayerRtt float64
	RTTDiff 	float64
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

	fmt.Printf("%d measurements.\n", len(ms))
	fmt.Printf("Min    RTT: %s\n", ms[0])
	fmt.Printf("Max    RTT: %s\n", ms[len(ms)-1])
	fmt.Printf("Mean   RTT: %s\n", mean(ms))
	fmt.Printf("Median RTT: %s\n", median(ms))
        allAppRTT := AppRTTStats{
		MinRTT: ms[0],
		MaxRTT: ms[len(ms)-1],
		MeanRTT: mean(ms),
		MedianRTT: median(ms),
	}
	return allAppRTT
}

