package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abo/rerate"
	"gopkg.in/redis.v5"
)

var (
	reverseProxy *httputil.ReverseProxy
	buckets      = rerate.NewRedisV5Buckets(redis.NewClient(&redis.Options{
		Addr: "redis:6379",
	}))
	initialRatePerSecond = int64(500)
	ratePerSecond        = &initialRatePerSecond
	limiter              = rerate.NewLimiter(buckets, "outproxy", 1*time.Second, time.Second/100, *ratePerSecond)
)

func handler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := strings.Split(r.RemoteAddr, ":")[0]
		count, err := limiter.Count(addr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintln(w, "Could not get count")
		}
		waitDur := time.Duration(int64(float64(count) / float64((*ratePerSecond)) * float64(time.Second.Nanoseconds())))
		if r.Method == "GET" && strings.HasPrefix(r.URL.String(), "/rem") {
			rem, err := limiter.Remaining(addr)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, "Could not get remaining")
			}
			fmt.Fprintf(w, "Remaining: %d, should sleep for %v\n", rem, waitDur)
			return
		}
		if r.Method == "POST" && strings.HasPrefix(r.URL.String(), "/rate") {
			bodyBytes, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(os.Stderr, "Error reading body from POST /rate: %v", err)
				return
			}
			newRate, err := strconv.ParseInt(string(bodyBytes), 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(os.Stderr, "Error parsing integer: %v", err)
				return
			}
			if newRate <= 0 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(os.Stderr, "New rate must be greater than 0")
				return
			}
			limiter = rerate.NewLimiter(buckets, "outproxy", 1*time.Second, time.Second/100, newRate)
			log.Printf("New rate set to %d per second", newRate)
			ratePerSecond = &newRate
			return
		}
		log.Println(r.Host + r.URL.String())
		if waitDur > 10*time.Millisecond {
			time.Sleep(waitDur)
		}
		exceeded, err := limiter.Exceeded(addr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "Couldn't get exceeded status: %v\n", err)
		} else {
			if exceeded {
				for exceeded {
					time.Sleep(waitDur)
					exceeded, err = limiter.Exceeded(addr)
					if exceeded {
						log.Println("Still exceeded!")
					}
				}
				// w.WriteHeader(http.StatusTooManyRequests)
				// fmt.Fprintln(w, "Rate exceeded")
				// return
			}
			if err := limiter.Inc(addr); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Could not increment rate counter: %v\n", err)
				return
			}
			for header, value := range r.Header {
				log.Printf("%s: %v\n", header, value)
			}
			p.ServeHTTP(w, r)
		}
	}
}

func main() {
	theURL, err := url.Parse("https://dumbserver/")
	if err != nil {
		panic(err)
	}
	log.Println("Parsed URL")
	reverseProxy := httputil.NewSingleHostReverseProxy(theURL)
	certPool := x509.NewCertPool()
	resp, err := http.Get("http://vault:8200/v1/pki/ca/pem")
	if err != nil {
		panic(err)
	}
	log.Println("Got CA from Vault")
	caContents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	log.Println("Read CA contents")
	ioutil.WriteFile("ca.pem", caContents, 0600)
	if !certPool.AppendCertsFromPEM(caContents) {
		panic("ohnoes")
	}
	log.Println("Loaded CA")
	reverseProxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: certPool,
		},
	}
	http.HandleFunc("/", handler(reverseProxy))
	err = http.ListenAndServe(":80", nil)
	if err != nil {
		panic(err)
	}
	log.Println("Done serving")
}
