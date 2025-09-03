package main

import (
	"github.com/conductorone/baton-sdk/pkg/config"
	cfg "github.com/conductorone/baton-tenable-vm/pkg/config"
)

func main() {
	config.Generate("tenable-vm", cfg.Config)
}
