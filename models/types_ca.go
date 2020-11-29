package models

import "time"

type CARequest struct {
	UID              string    `json:"uid,omitempty"`
	Name             string    `json:"name"`
	CommonName       string    `json:"common_name"`
	Organisation     string    `json:"organisation,omitempty"`
	Validity         int       `json:"validity,omitempty"`
	SigningAlgorithm string    `json:"signing_algorithm,omitempty"`
	CreateAt         time.Time `json:"create_at,omitempty"`
	IsCA             bool      `json:"is_ca"`
}

type CA struct {
	CACert string
	CAKey  string
}
