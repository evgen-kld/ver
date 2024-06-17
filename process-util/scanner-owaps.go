package main

import (
	"encoding/json"
	"os"
	"strconv"
)

func parseOwasp(file string) (ScanResult, error) {
	type owaspJson struct {
		Site []struct {
			Alerts []struct {
				Pluginid   string `json:"pluginid"`
				AlertRef   string `json:"alertRef"`
				Alert      string `json:"alert"`
				Name       string `json:"name"`
				Riskcode   string `json:"riskcode"`
				Confidence string `json:"confidence"`
				Riskdesc   string `json:"riskdesc"`
				Desc       string `json:"desc"`
				Instances  []struct {
					Uri            string `json:"uri"`
					Method         string `json:"method"`
					Param          string `json:"param"`
					Attack         string `json:"attack"`
					Evidence       string `json:"evidence"`
					Otherinfo      string `json:"otherinfo"`
					RequestHeader  string `json:"request-header"`
					RequestBody    string `json:"request-body"`
					ResponseHeader string `json:"response-header"`
					ResponseBody   string `json:"response-body"`
				} `json:"instances"`
				Count     string `json:"count"`
				Solution  string `json:"solution"`
				Otherinfo string `json:"otherinfo"`
				Reference string `json:"reference"`
				Cweid     string `json:"cweid"`
				Wascid    string `json:"wascid"`
				Sourceid  string `json:"sourceid"`
				Tags      []struct {
					Tag  string `json:"tag"`
					Link string `json:"link"`
				} `json:"tags"`
			} `json:"alerts"`
		} `json:"site"`
	}

	data, err := os.ReadFile("./" + file)
	if err != nil {
		return ScanResult{}, err
	}

	var jsonData owaspJson
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return ScanResult{}, err
	}

	scanResult := ScanResult{
		Type: DYNAMIC_ANALYZER_TYPE,
		Name: ANALYZER_OWASP,
	}

	for _, issue := range jsonData.Site[0].Alerts {
		level, _ := strconv.Atoi(issue.Riskcode)
		confidence, _ := strconv.Atoi(issue.Confidence)
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, Vulnerability{
			DastInfo: DastInfo{
				Url:    issue.Instances[0].Uri,
				Method: issue.Instances[0].Method,
			},
			Level:       level,
			Confidence:  confidence,
			Description: issue.Desc,
			Links:       []string{issue.Otherinfo},
			CweId:       issue.Cweid,
		})
	}

	return scanResult, nil
}
