package assets

import (
	"embed"
)

// SwaggerUI contains the static files that make up the Swagger UI
//
//go:embed swagger/*
var SwaggerUI embed.FS
