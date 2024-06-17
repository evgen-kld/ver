package main

import (
	"encoding/json"
	"os"
	"strconv"
)

func parseSemgrep(file string) (ScanResult, error) {
	type semgrepJson struct {
		Results []struct {
			CheckId string `json:"check_id"`
			End     struct {
				Col    int `json:"col"`
				Line   int `json:"line"`
				Offset int `json:"offset"`
			} `json:"end"`
			Extra struct {
				Lines    string `json:"lines"`
				Message  string `json:"message"`
				Metadata struct {
					Category   string   `json:"category"`
					Confidence string   `json:"confidence"`
					Cwe        []string `json:"cwe"`
					Owasp      []string `json:"owasp"`
					References []string `json:"references"`
				} `json:"metadata"`

				Severity        string `json:"severity"`
				ValidationState string `json:"validation_state"`
			} `json:"extra"`
			Path  string `json:"path"`
			Start struct {
				Col    int `json:"col"`
				Line   int `json:"line"`
				Offset int `json:"offset"`
			} `json:"start"`
		} `json:"results"`
		SkippedRules []interface{} `json:"skipped_rules"`
		Version      string        `json:"version"`
	}

	data, err := os.ReadFile("./" + file)
	if err != nil {
		return ScanResult{}, err
	}

	var jsonData semgrepJson
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return ScanResult{}, err
	}

	severityMap := map[string]int{
		"WARNING": 1,
		"MEDIUM":  2,
		"ERROR":   3,
	}

	confidenceMap := map[string]int{
		"LOW":    1,
		"MEDIUM": 2,
		"HIGH":   3,
	}

	scanResult := ScanResult{
		Type: STATIC_ANALYZER_TYPE,
		Name: ANALYZER_SEMGREP,
	}

	for _, issue := range jsonData.Results {
		level := severityMap[issue.Extra.Severity]
		confidence := confidenceMap[issue.Extra.Metadata.Confidence]
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, Vulnerability{
			SastInfo: SastInfo{
				File:   issue.Path,
				Line:   strconv.Itoa(issue.Start.Line),
				String: issue.Extra.Lines,
			},
			Level:       level,
			Confidence:  confidence,
			Description: issue.Extra.Message,
			Links:       issue.Extra.Metadata.References,
			CweId:       issue.Extra.Metadata.Cwe[0],
			OwaspId:     issue.Extra.Metadata.Owasp[0],
		})
	}

	return scanResult, nil
}
