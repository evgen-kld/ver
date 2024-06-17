package models

type ScanResult struct {
	Type            int    `json:"type"`
	Name            string `json:"name"`
	Vulnerabilities []Vulnerability
}

type Vulnerability struct {
	SastInfo    *SastInfo `json:"sast_info"`
	DastInfo    *DastInfo `json:"dast_info"`
	Level       int       `json:"level"`
	Confidence  int       `json:"confidence"`
	Description string    `json:"description"`
	Links       []string  `json:"links"`
	CweId       string    `json:"cwe_id"`
	OwaspId     string    `json:"owasp_id"`
}

type SastInfo struct {
	File   string `json:"file"`
	Line   string `json:"line"`
	String string `json:"string"`
}

type DastInfo struct {
	Url    string `json:"url"`
	Method string `json:"method"`
}
