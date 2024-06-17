package handlers

import (
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"vulnerability_handler/database"
	"vulnerability_handler/models"
	"vulnerability_handler/utils"
)

func ProcessVulnerabilities(w http.ResponseWriter, r *http.Request) {
	var scanResult []models.ScanResult
	err := json.NewDecoder(r.Body).Decode(&scanResult)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	vulnerabilities := mergeVulnerabilities(scanResult)

	dbVulnerabilities, err := database.GetVulnerabilities()
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	flag := true
	for _, vulnerability := range vulnerabilities {
		isInDb := false
		for _, dbVulnerability := range dbVulnerabilities {
			if vulnerability.DastInfo != nil && dbVulnerability.Vulnerability.DastInfo != nil {
				if vulnerability.CweId == dbVulnerability.Vulnerability.CweId &&
					vulnerability.DastInfo.Url == dbVulnerability.Vulnerability.DastInfo.Url &&
					vulnerability.DastInfo.Method == dbVulnerability.Vulnerability.DastInfo.Method {
					isInDb = true
					if dbVulnerability.Status != "skipped" {
						flag = false
					}
					break
				}
			}
			if vulnerability.SastInfo != nil && dbVulnerability.Vulnerability.SastInfo != nil {
				if vulnerability.CweId == dbVulnerability.Vulnerability.CweId &&
					vulnerability.SastInfo.Line == dbVulnerability.Vulnerability.SastInfo.Line {
					isInDb = true
					if dbVulnerability.Status != "skipped" {
						flag = false
					}
					break
				}
			}
		}

		if !isInDb {
			err = database.AddVulnerability(vulnerability)
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
				return
			}
			flag = false
		}
	}

	for _, dbVulnerability := range dbVulnerabilities {
		isFixed := true
		for _, vulnerability := range vulnerabilities {
			if vulnerability.SastInfo != nil && dbVulnerability.Vulnerability.SastInfo != nil {
				if vulnerability.CweId == dbVulnerability.Vulnerability.CweId &&
					vulnerability.SastInfo.Line == dbVulnerability.Vulnerability.SastInfo.Line {
					isFixed = false
					break
				}
			}
		}
		if isFixed {
			err := database.UpdateVulnerabilityStatus(dbVulnerability.Id, "fixed")
			if err != nil {
				utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}

	if !flag {
		utils.RespondWithJSON(w, http.StatusOK, map[string]bool{"status": false})
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]bool{"status": true})
}

func GetVulnerabilities(w http.ResponseWriter, r *http.Request) {
	dbVulnerabilities, err := database.GetVulnerabilities()
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string][]models.DbVulnerability{"list": dbVulnerabilities})
}

func SetSkippedById(w http.ResponseWriter, r *http.Request) {
	idParam := r.URL.Query().Get("id")
	if idParam == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "ID parameter is required")
		return
	}

	id, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	err = database.UpdateVulnerabilityStatus(id, "skipped")
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]bool{"status": true})
}

func mergeVulnerabilities(scanResults []models.ScanResult) []models.Vulnerability {
	vulnMap := make(map[string]models.Vulnerability)
	for _, scanResult := range scanResults {
		for _, vulnerability := range scanResult.Vulnerabilities {
			if scanResult.Type == 1 {
				key := fmt.Sprintf("%s-%s", vulnerability.SastInfo.Line, vulnerability.CweId)
				existingVuln, exists := vulnMap[key]
				if exists {
					if vulnerability.Level > existingVuln.Level {
						existingVuln.Level = vulnerability.Level
					}
					if vulnerability.Confidence > existingVuln.Confidence {
						existingVuln.Confidence = vulnerability.Confidence
					}
					vulnMap[key] = existingVuln
				} else {
					vulnMap[key] = vulnerability
				}
			}
		}
	}

	// Convert map to slice
	mergedVulns := make([]models.Vulnerability, 0, len(vulnMap))
	for _, vuln := range vulnMap {
		mergedVulns = append(mergedVulns, vuln)
	}

	return mergedVulns
}
