package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// Response representa a estrutura de resposta da API
type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func main() {
	version := os.Getenv("VERSION")
	if version == "" {
		version = "A" // Default to version A if not specified
	}

	// Função para renderizar o template com Tailwind CSS
	renderTemplate := func(w http.ResponseWriter, title, description, payload, attackType string) {
		html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="pt-BR">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Valsec - %s</title>
			<script src="https://cdn.tailwindcss.com"></script>
			<script>
				tailwind.config = {
					darkMode: 'class',
					theme: {
						extend: {
							colors: {
								primary: '#6366f1',
								secondary: '#8b5cf6',
								danger: '#ef4444',
							}
						}
					}
				}
			</script>
		</head>
		<body class="bg-gray-900 text-gray-100 min-h-screen flex items-center justify-center p-4">
			<div class="max-w-2xl w-full bg-gray-800 rounded-lg shadow-xl overflow-hidden">
				<div class="bg-gradient-to-r from-primary to-secondary p-4">
					<h1 class="text-2xl font-bold text-white">%s</h1>
				</div>
				<div class="p-6">
					<div class="mb-6">
						<h2 class="text-xl font-semibold text-gray-200 mb-2">Descrição do Teste</h2>
						<p class="text-gray-300">%s</p>
					</div>
					
					<div class="mb-6">
						<h2 class="text-xl font-semibold text-gray-200 mb-2">Payload Detectado</h2>
						<div class="bg-gray-700 p-3 rounded-md">
							<code class="text-amber-400 break-all">%s</code>
						</div>
					</div>
					
					<div class="bg-red-900/30 border border-red-500/50 rounded-md p-4 mb-6">
						<div class="flex items-start">
							<svg class="w-6 h-6 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
							</svg>
							<div>
								<h3 class="text-lg font-medium text-red-400">Alerta de Segurança</h3>
								<p class="text-gray-300 mt-1">Este é um teste de segurança para verificar proteções contra ataques de %s. Em um ambiente real, este tipo de requisição seria bloqueado pelo Cloudflare OWASP Core Ruleset.</p>
							</div>
						</div>
					</div>
					
					<div class="flex justify-between">
						<a href="/" class="inline-flex items-center px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-md transition-colors">
							<svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
							</svg>
							Voltar
						</a>
						<span class="text-sm text-gray-400">Valsec Security Testing</span>
					</div>
				</div>
			</div>
		</body>
		</html>
		`, title, title, description, payload, attackType)
		
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	}

	// Endpoint para simulação de SQL Injection
	http.HandleFunc("/sql-injection", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		log.Printf("SQL Injection Test - ID: %s", id)
		
		title := "Teste de SQL Injection"
		description := "Este teste simula uma tentativa de injeção SQL que poderia ser usada para manipular consultas ao banco de dados, extrair informações sensíveis ou executar comandos não autorizados."
		payload := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
		attackType := "SQL Injection"
		
		renderTemplate(w, title, description, payload, attackType)
	})

	// Endpoint para simulação de XSS (Cross-Site Scripting)
	http.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		log.Printf("XSS Test - Name: %s", name)
		
		title := "Teste de Cross-Site Scripting (XSS)"
		description := "Este teste simula uma tentativa de injeção de scripts maliciosos que poderiam ser executados no navegador de outros usuários, permitindo roubo de sessões, redirecionamentos maliciosos ou outras ações não autorizadas."
		payload := name
		attackType := "Cross-Site Scripting"
		
		renderTemplate(w, title, description, payload, attackType)
	})

	// Endpoint para simulação de Command Injection
	http.HandleFunc("/command-injection", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		log.Printf("Command Injection Test - Host: %s", host)
		
		title := "Teste de Command Injection"
		description := "Este teste simula uma tentativa de injeção de comandos do sistema operacional que poderiam ser executados no servidor, permitindo acesso não autorizado a arquivos, execução de programas maliciosos ou comprometimento do sistema."
		payload := fmt.Sprintf("ping -c 1 %s", host)
		attackType := "Command Injection"
		
		renderTemplate(w, title, description, payload, attackType)
	})

	// Endpoint para simulação de Path Traversal
	http.HandleFunc("/path-traversal", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		log.Printf("Path Traversal Test - File: %s", file)
		
		title := "Teste de Path Traversal"
		description := "Este teste simula uma tentativa de acesso a arquivos fora do diretório permitido, o que poderia expor arquivos sensíveis do sistema, configurações ou dados privados."
		payload := fmt.Sprintf("open('%s', 'r')", file)
		attackType := "Path Traversal"
		
		renderTemplate(w, title, description, payload, attackType)
	})

	// Endpoint para simulação de Local File Inclusion (LFI)
	http.HandleFunc("/lfi", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		log.Printf("LFI Test - Page: %s", page)
		
		title := "Teste de Local File Inclusion"
		description := "Este teste simula uma tentativa de inclusão de arquivos locais não autorizados, o que poderia permitir a execução de código malicioso, acesso a informações sensíveis ou comprometimento do sistema."
		payload := fmt.Sprintf("include('%s')", page)
		attackType := "Local File Inclusion"
		
		renderTemplate(w, title, description, payload, attackType)
	})
	
	// Endpoint para simulação de API Test
	http.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			id = "1 OR 1=1"
		}
		log.Printf("API Test - ID: %s", id)
		
		// Resposta JSON para teste de API
		response := Response{
			Status: "success",
			Message: fmt.Sprintf("Teste de API com parâmetro potencialmente malicioso: %s", id),
			Data: map[string]interface{}{
				"query": fmt.Sprintf("SELECT * FROM users WHERE id = %s", id),
				"timestamp": time.Now().Unix(),
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	// Endpoint para API POST (diferente do GET acima)
	http.HandleFunc("/api/post", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
			return
		}
		
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Erro ao ler o corpo da requisição", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		
		log.Printf("API POST Test - Payload: %s", string(body))
		
		// Resposta para teste de API
		response := Response{
			Status:  "success",
			Message: "Payload recebido com sucesso",
			Data:    string(body),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Log da requisição recebida
		log.Printf("Request recebida: %s %s de %s", r.Method, r.URL.Path, r.RemoteAddr)

		var versionColor string
		var versionText string

		switch version {
		case "A":
			versionColor = "indigo-500"
			versionText = "Versão A"
		case "B":
			versionColor = "emerald-500"
			versionText = "Versão B"
		default:
			versionColor = "indigo-500"
			versionText = "Versão A"
		}

		html := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="pt-BR">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Valsec - Security Testing</title>
			<script src="https://cdn.tailwindcss.com"></script>
			<script>
				tailwind.config = {
					darkMode: 'class',
					theme: {
						extend: {
							colors: {
								primary: '#6366f1',
								secondary: '#8b5cf6',
								danger: '#ef4444',
							}
						}
					}
				}
			</script>
		</head>
		<body class="bg-gray-900 text-gray-100 min-h-screen">
			<div class="absolute top-2 right-2 bg-gray-800/70 px-3 py-1 rounded-full text-sm font-medium text-%s">
				%s
			</div>
			
			<div class="absolute bottom-2 left-2 bg-gray-800/70 px-3 py-1 rounded-full text-xs text-gray-400">
				Hostname: %s
			</div>
			
			<div class="container mx-auto px-4 py-16">
				<div class="text-center mb-16">
					<h1 class="text-5xl font-bold bg-gradient-to-r from-primary to-secondary inline-block text-transparent bg-clip-text mb-4">Valsec</h1>
					<p class="text-xl text-gray-300">Plataforma de Testes de Segurança</p>
				</div>
				
				<div class="max-w-4xl mx-auto bg-gray-800 rounded-lg shadow-xl overflow-hidden">
					<div class="bg-gradient-to-r from-primary to-secondary p-4">
						<h2 class="text-2xl font-bold text-white">Testes de Segurança Disponíveis</h2>
					</div>
					
					<div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-4">
						<a href="/sql-injection?id=1' OR '1'='1" class="block bg-gray-700 hover:bg-gray-600 p-4 rounded-lg transition-colors">
							<div class="flex items-start">
								<div class="bg-red-500/20 p-2 rounded-md mr-3">
									<svg class="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path>
									</svg>
								</div>
								<div>
									<h3 class="text-lg font-medium text-white">SQL Injection</h3>
									<p class="text-gray-400 mt-1">Teste de injeção SQL para manipulação de consultas ao banco de dados</p>
								</div>
							</div>
						</a>
						
						<a href="/xss?name=<script>alert('XSS')</script>" class="block bg-gray-700 hover:bg-gray-600 p-4 rounded-lg transition-colors">
							<div class="flex items-start">
								<div class="bg-orange-500/20 p-2 rounded-md mr-3">
									<svg class="w-6 h-6 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
									</svg>
								</div>
								<div>
									<h3 class="text-lg font-medium text-white">Cross-Site Scripting (XSS)</h3>
									<p class="text-gray-400 mt-1">Teste de injeção de scripts maliciosos no navegador</p>
								</div>
							</div>
						</a>
						
						<a href="/command-injection?host=localhost;ls" class="block bg-gray-700 hover:bg-gray-600 p-4 rounded-lg transition-colors">
							<div class="flex items-start">
								<div class="bg-yellow-500/20 p-2 rounded-md mr-3">
									<svg class="w-6 h-6 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
									</svg>
								</div>
								<div>
									<h3 class="text-lg font-medium text-white">Command Injection</h3>
									<p class="text-gray-400 mt-1">Teste de injeção de comandos do sistema operacional</p>
								</div>
							</div>
						</a>
						
						<a href="/path-traversal?file=../../../etc/passwd" class="block bg-gray-700 hover:bg-gray-600 p-4 rounded-lg transition-colors">
							<div class="flex items-start">
								<div class="bg-green-500/20 p-2 rounded-md mr-3">
									<svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
									</svg>
								</div>
								<div>
									<h3 class="text-lg font-medium text-white">Path Traversal</h3>
									<p class="text-gray-400 mt-1">Teste de acesso a arquivos fora do diretório permitido</p>
								</div>
							</div>
						</a>
						
						<a href="/lfi?page=../../../etc/passwd" class="block bg-gray-700 hover:bg-gray-600 p-4 rounded-lg transition-colors">
							<div class="flex items-start">
								<div class="bg-blue-500/20 p-2 rounded-md mr-3">
									<svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
									</svg>
								</div>
								<div>
									<h3 class="text-lg font-medium text-white">Local File Inclusion</h3>
									<p class="text-gray-400 mt-1">Teste de inclusão de arquivos locais não autorizados</p>
								</div>
							</div>
						</a>
						
						<a href="/api/test" class="block bg-gray-700 hover:bg-gray-600 p-4 rounded-lg transition-colors">
							<div class="flex items-start">
								<div class="bg-purple-500/20 p-2 rounded-md mr-3">
									<svg class="w-6 h-6 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path>
									</svg>
								</div>
								<div>
									<h3 class="text-lg font-medium text-white">API Test</h3>
									<p class="text-gray-400 mt-1">Teste de endpoints de API com parâmetros maliciosos</p>
								</div>
							</div>
						</a>
					</div>
					
					<div class="p-4 bg-gray-700 text-center">
						<p class="text-gray-400 text-sm">Estes testes são destinados a verificar a eficácia das proteções de segurança do Cloudflare.</p>
					</div>
				</div>
			</div>
		</body>
		</html>
		`, versionColor, versionText, getHostname())

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
