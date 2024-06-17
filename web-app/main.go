package main

import (
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"log"
	"net/http"
	"vulnerability_handler/config"
	"vulnerability_handler/database"
	"vulnerability_handler/handlers"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
}

func main() {
	config.LoadConfig()
	database.ConnectDB()

	r := mux.NewRouter()
	r.HandleFunc("/process-vulnerabilities", handlers.ProcessVulnerabilities).Methods("POST")
	r.HandleFunc("/get-vulnerabilities", handlers.GetVulnerabilities).Methods("GET")
	r.HandleFunc("/set-skipped-by-id", handlers.SetSkippedById).Methods("GET")

	// Настройка CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}).Handler(r)

	log.Println("Server is running on port 8889")
	log.Fatal(http.ListenAndServe(":8889", corsHandler))
}
