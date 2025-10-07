package main

import (
"fmt"
"log"
"net/http"
"os"
)

func main() {
	version := os.Getenv("VERSION")
	if version == "" {
		version = "A" // Default to version A if not specified
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
// Log da requisição recebida
log.Printf("Request recebida: %s %s de %s", r.Method, r.URL.Path, r.RemoteAddr)

var backgroundColor, versionText string

switch version {
case "A":
backgroundColor = "#FF69B4" // Pink
versionText = "Versão A (Rosa)"
case "B":
backgroundColor = "#1E90FF" // Blue
versionText = "Versão B (Azul)"
default:
backgroundColor = "#FF69B4" // Default to pink
versionText = "Versão A (Rosa)"
}

html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<title>Valsec - %s</title>
			<style>
				body {
					background-color: %s;
					color: white;
					font-family: Arial, sans-serif;
					display: flex;
					flex-direction: column;
					align-items: center;
					justify-content: center;
					height: 100vh;
					margin: 0;
				}
				h1 {
					font-size: 3em;
					text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
				}
				.info {
					margin-top: 20px;
					font-size: 1.2em;
				}
			</style>
		</head>
		<body>
			<h1>Valsec</h1>
			<div class="info">
				<p>%s</p>
				<p>Hostname: %s</p>
			</div>
		</body>
		</html>
		`, versionText, backgroundColor, versionText, getHostname())

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
		
		// Log após o envio da resposta
		log.Printf("Resposta enviada para %s: %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Iniciando servidor na porta %s com versão %s", port, version)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "Desconhecido"
	}
	return hostname
}
