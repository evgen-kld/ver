package database

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
	"vulnerability_handler/config"
	"vulnerability_handler/models"
)

var Client *mongo.Client

func ConnectDB() {
	clientOptions := options.Client().ApplyURI(config.MongoURI)

	client, err := mongo.NewClient(clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Connected to MongoDB!")
	Client = client
}

func GetCollection(collectionName string) *mongo.Collection {
	collection := Client.Database("vulnerabilities_db").Collection(collectionName)
	return collection
}

func AddVulnerability(vulnerability models.Vulnerability) error {
	collection := Client.Database("vulnerabilities_db").Collection("vulnerabilities")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dbVuln := models.DbVulnerability{
		Vulnerability: vulnerability,
		Status:        "new",
	}
	_, err := collection.InsertOne(ctx, dbVuln)
	if err != nil {
		return err
	}

	return nil
}

func GetVulnerabilities() ([]models.DbVulnerability, error) {
	collection := Client.Database("vulnerabilities_db").Collection("vulnerabilities")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var vulnerabilities []models.DbVulnerability
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var vuln models.DbVulnerability
		if err := cursor.Decode(&vuln); err != nil {
			return nil, err
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return vulnerabilities, nil
}

func UpdateVulnerabilityStatus(vulnerabilityID primitive.ObjectID, newStatus string) error {
	collection := Client.Database("vulnerabilities_db").Collection("vulnerabilities")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{"_id": vulnerabilityID}
	update := bson.M{
		"$set": bson.M{
			"status": newStatus,
		},
	}

	_, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}

	return nil
}
