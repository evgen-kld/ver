package main

import (
	"encoding/json"
	"log"
	"os"
)

func parseGosec(file string) (ScanResult, error) {
	type gosecJson struct {
		Issues []struct {
			Severity   string `json:"severity"`
			Confidence string `json:"confidence"`
			Cwe        struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			} `json:"cwe"`
			Details string `json:"details"`
			File    string `json:"file"`
			Code    string `json:"code"`
			Line    string `json:"line"`
		} `json:"issues"`
	}

	data, err := os.ReadFile("./" + file)
	if err != nil {
		log.Fatal(err)
		return ScanResult{}, err
	}

	var jsonData gosecJson
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return ScanResult{}, err
	}

	severityMap := map[string]int{
		"LOW":    1,
		"MEDIUM": 2,
		"HIGH":   3,
	}

	confidenceMap := map[string]int{
		"LOW":    1,
		"MEDIUM": 2,
		"HIGH":   3,
	}

	scanResult := ScanResult{
		Type: STATIC_ANALYZER_TYPE,
		Name: ANALYZER_GOSEC,
	}

	for _, issue := range jsonData.Issues {
		level := severityMap[issue.Severity]
		confidence := confidenceMap[issue.Confidence]

		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, Vulnerability{
			SastInfo: SastInfo{
				File:   issue.File,
				Line:   issue.Line,
				String: issue.Code,
			},
			Level:       level,
			Confidence:  confidence,
			Description: issue.Details,
			Links:       []string{issue.Cwe.URL},
			CweId:       issue.Cwe.ID,
			OwaspId:     "",
		})
	}

	return scanResult, nil
}
