package main

import (
	"context"
	"encoding/base64"
	"flag"
	"github.com/guoyk93/rg"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func extractProxyBasicAuth(req *http.Request) (username, password string, ok bool) {
	auth := req.Header.Get("Proxy-Authorization")
	if auth == "" {
		return
	}
	req.Header.Del("Proxy-Authorization")
	const prefix = "Basic "
	if len(auth) < len(prefix) || strings.ToLower(prefix) != strings.ToLower(auth[:len(prefix)]) {
		return
	}
	if c, err := base64.StdEncoding.DecodeString(auth[len(prefix):]); err == nil {
		username, password, ok = strings.Cut(string(c), ":")
	}
	return
}

func handleProxyConnect(dialer proxy.ContextDialer, rw http.ResponseWriter, req *http.Request) {
	// dial upstream
	sconn, err := dialer.DialContext(req.Context(), "tcp", req.Host)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	defer sconn.Close()

	// check hackable
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		http.Error(rw, "failed to cast to http.Hijacker", http.StatusInternalServerError)
		return
	}

	// seems 200 should send before Hijack()
	rw.WriteHeader(200)

	// hijack
	conn, bio, err := hijacker.Hijack()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// bi-directional copy
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(sconn, bio)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(bio, sconn)
	}()
	wg.Wait()
}

func handleProxyRequest(client *http.Client, rw http.ResponseWriter, req *http.Request) {
	// Server-Only field; we get an error fi we pass this to `client.Do`.
	req.RequestURI = ""

	// do request
	resp, err := client.Do(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// copy and send header
	for k, v := range resp.Header {
		rw.Header()[k] = v
	}
	rw.WriteHeader(resp.StatusCode)

	// send body
	_, _ = io.Copy(rw, resp.Body)
}

func main() {
	var err error
	defer func() {
		if err == nil {
			return
		}
		log.Println("exited with error:", err.Error())
		os.Exit(1)
	}()
	defer rg.Guard(&err)

	var (
		optListen string
		optServer string

		optProxyUsername    = strings.TrimSpace(os.Getenv("PROXY_USERNAME"))
		optProxyPassword    = strings.TrimSpace(os.Getenv("PROXY_PASSWORD"))
		optUpstreamUsername = strings.TrimSpace(os.Getenv("UPSTREAM_USERNAME"))
		optUpstreamPassword = strings.TrimSpace(os.Getenv("UPSTREAM_PASSWORD"))
	)

	flag.StringVar(&optListen, "l", ":1087", "address to listen on")
	flag.StringVar(&optServer, "s", "127.0.0.1:1080", "upstream socks server to connect to")
	flag.Parse()

	var upstreamAuth *proxy.Auth

	if optUpstreamUsername != "" && optUpstreamPassword != "" {
		upstreamAuth = &proxy.Auth{
			User:     optUpstreamUsername,
			Password: optUpstreamPassword,
		}
	}

	upstreamDialer := rg.Must(proxy.SOCKS5("tcp", optServer, upstreamAuth, proxy.Direct)).(proxy.ContextDialer)

	upstreamClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (c net.Conn, err error) {
				return upstreamDialer.DialContext(ctx, network, addr)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	s := &http.Server{
		Addr: optListen,
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			// check basic auth
			if optProxyUsername != "" && optProxyPassword != "" {
				if username, password, ok := extractProxyBasicAuth(req); !ok || username != optProxyUsername || password != optProxyPassword {
					http.Error(rw, "invalid basic auth", http.StatusForbidden)
					return
				}
			}

			if req.Method == http.MethodConnect {
				handleProxyConnect(upstreamDialer, rw, req)
			} else {
				handleProxyRequest(upstreamClient, rw, req)
			}
		}),
	}

	chErr := make(chan error, 1)
	chSig := make(chan os.Signal, 1)
	signal.Notify(chSig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Println("starting", optListen, "->", optServer)
		chErr <- s.ListenAndServe()
	}()

	select {
	case err = <-chErr:
		return
	case sig := <-chSig:
		log.Println("signal caught:", sig.String())
		time.Sleep(time.Second * 3)
	}

	err = s.Shutdown(context.Background())
}
