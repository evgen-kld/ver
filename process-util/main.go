package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	STATIC_ANALYZER_TYPE  = 1
	DYNAMIC_ANALYZER_TYPE = 2
	ANALYZER_GOSEC        = "gosec"
	ANALYZER_OWASP        = "owasp"
	ANALYZER_SEMGREP      = "semgrep"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Необходимо передать минимум один результат сканирования")
	}

	var gosecFile, semgrepFile, owaspFile string

	for _, arg := range os.Args[1:] {
		if strings.Contains(arg, "gosec") {
			gosecFile = arg
		} else if strings.Contains(arg, "semgrep") {
			semgrepFile = arg
		} else if strings.Contains(arg, "owasp") {
			owaspFile = arg
		}

	}

	var scanResult []ScanResult

	if gosecFile != "" {
		gosecRes, err := parseGosec(gosecFile)
		if err != nil {
			log.Fatal(err)
		}
		scanResult = append(scanResult, gosecRes)
	}

	if semgrepFile != "" {
		semgrepRes, err := parseSemgrep(semgrepFile)
		if err != nil {
			log.Fatal(err)
		}
		scanResult = append(scanResult, semgrepRes)
	}

	if owaspFile != "" {
		owaspRes, err := parseOwasp(owaspFile)
		if err != nil {
			log.Fatal(err)
		}
		scanResult = append(scanResult, owaspRes)
	}

	processed := sendResults(scanResult)

	if processed {
		fmt.Println("Необработанные уязвимости отсутствуют.")
		os.Exit(0)
	} else {
		fmt.Println("Обнаружены необработанные уязвимости.")
		os.Exit(1)
	}
}

func sendResults(results []ScanResult) bool {
	data, err := json.Marshal(results)
	if err != nil {
		log.Printf("Error marshalling results: %v", err)
		return false
	}

	resp, err := http.Post("http://194.67.119.42:8889/process-vulnerabilities", "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Error sending SAST result: %v", err)
		return false
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		return false
	}

	var response map[string]bool
	err = json.Unmarshal(body, &response)
	if err != nil {
		log.Printf("Error unmarshalling response: %v", err)
		return false
	}

	if response["status"] != true {
		return false
	}

	return true
}
