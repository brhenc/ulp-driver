package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
)

type StatusResponse struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Version string `json:"version"`
	Counter uint64 `json:"counter"`
	CPUs    int    `json:"cpus"`
}

var reqCounter uint64

//go:noinline
func GetServiceStatus() string {
	return "ORIGINAL_UNPATCHED_GO_SERVICE"
}

//go:noinline
func GetVersionTag() string {
	return "v1.0.0-GA"
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	c := atomic.AddUint64(&reqCounter, 1)
	resp := StatusResponse{
		Service: "Project-ulp-driver-OpenAPI",
		Status:  GetServiceStatus(),
		Version: GetVersionTag(),
		Counter: c,
		CPUs:    runtime.NumCPU(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	http.HandleFunc("/api/v1/status", statusHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "STATUS:%s|VERSION:%s\n", GetServiceStatus(), GetVersionTag())
	})
	fmt.Printf("[+] Go REST Server listening on :9090 (GOMAXPROCS=%d)\n", runtime.NumCPU())
	if err := http.ListenAndServe(":9090", nil); err != nil {
		panic(err)
	}
}
