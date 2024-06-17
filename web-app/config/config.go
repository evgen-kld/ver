package config

import (
	"log"
	"os"
)

var MongoURI string
var MongoDatabase string
var ServerPort string

func LoadConfig() {
	MongoURI = os.Getenv("MONGO_URI")
	if MongoURI == "" {
		log.Fatal("MONGO_URI is not set")
	}
	MongoDatabase = os.Getenv("MONGO_DATABASE")
	if MongoDatabase == "" {
		log.Fatal("MONGO_DATABASE is not set")
	}
	ServerPort = os.Getenv("SERVER_PORT")
	if ServerPort == "" {
		log.Fatal("SERVER_PORT is not set")
	}
}
