package kev

import (
	"encoding/json"
	"log"
)

type KEV struct {
	db      *db
	catalog *Catalog
}

func New() *KEV {
	return &KEV{
		db: newDB(),
	}
}

func (k *KEV) Init() error {
	log.Println("Initializing KEV")
	needsUpdate, err := k.db.needsUpdate()
	if err != nil {
		return err
	}
	if needsUpdate {
		log.Println("Downloading KEV")
		if err := k.db.download(); err != nil {
			return err
		}
	} else {
		log.Println("Skip downloading KEV")
	}

	buf, err := k.db.read()
	if err != nil {
		return err
	}

	catalog := &Catalog{}
	if err := json.Unmarshal(buf, catalog); err != nil {
		return err
	}
	k.catalog = catalog

	return nil
}

func (k *KEV) Catalog() *Catalog {
	return k.catalog
}
