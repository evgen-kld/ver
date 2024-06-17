package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type DbVulnerability struct {
	Id            primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Vulnerability Vulnerability      `bson:"vulnerability" json:"vulnerability"`
	Status        string             `bson:"status" json:"status"`
}
