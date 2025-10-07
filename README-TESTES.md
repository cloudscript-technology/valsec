# Testes de Segurança - Valsec

Este documento contém exemplos de requisições para testar as proteções do Cloudflare OWASP Core Ruleset usando a aplicação Valsec.

## Objetivo

O objetivo destes testes é verificar se as proteções do Cloudflare OWASP Core Ruleset estão funcionando corretamente para bloquear diferentes tipos de ataques.

## URL da Aplicação

```
https://valsec.example.com
```

## Tipos de Ataques para Teste

### 1. SQL Injection

Estes testes simulam tentativas de injeção de SQL para explorar vulnerabilidades no banco de dados.

```
GET https://valsec.example.com/sql-injection?id=1%20OR%201=1
```
- **Descrição**: Tenta retornar todos os registros usando a condição OR 1=1

```
GET https://valsec.example.com/sql-injection?id=1;%20DROP%20TABLE%20users
```
- **Descrição**: Tenta executar um comando DROP TABLE para excluir uma tabela

```
GET https://valsec.example.com/sql-injection?id=1%20UNION%20SELECT%20username,password%20FROM%20users
```
- **Descrição**: Tenta extrair senhas usando UNION SELECT

### 2. Cross-Site Scripting (XSS)

Estes testes simulam tentativas de injeção de scripts maliciosos.

```
GET https://valsec.example.com/xss?name=<script>alert('XSS')</script>
```
- **Descrição**: Tenta injetar um script de alerta básico

```
GET https://valsec.example.com/xss?name=<img%20src='x'%20onerror='alert("XSS")'>
```
- **Descrição**: Tenta executar código JavaScript através do evento onerror de uma imagem

```
GET https://valsec.example.com/xss?name=<iframe%20src='javascript:alert("XSS")'></iframe>
```
- **Descrição**: Tenta injetar um iframe malicioso com código JavaScript

### 3. Command Injection

Estes testes simulam tentativas de injeção de comandos no sistema operacional.

```
GET https://valsec.example.com/command-injection?host=localhost;%20ls%20-la
```
- **Descrição**: Tenta listar arquivos do servidor usando o comando ls -la

```
GET https://valsec.example.com/command-injection?host=localhost%20|%20cat%20/etc/passwd
```
- **Descrição**: Tenta ler o arquivo de senhas do sistema usando pipe

```
GET https://valsec.example.com/command-injection?host=localhost%20&&%20whoami
```
- **Descrição**: Tenta descobrir o usuário que está executando o servidor

### 4. Path Traversal

Estes testes simulam tentativas de acesso a arquivos fora do diretório permitido.

```
GET https://valsec.example.com/path-traversal?file=../../../etc/passwd
```
- **Descrição**: Tenta acessar o arquivo de senhas do sistema usando path traversal

```
GET https://valsec.example.com/path-traversal?file=../../../etc/shadow
```
- **Descrição**: Tenta acessar o arquivo de hashes de senhas do sistema

```
GET https://valsec.example.com/path-traversal?file=../../../var/log/syslog
```
- **Descrição**: Tenta acessar os logs do sistema

### 5. Local File Inclusion (LFI)

Estes testes simulam tentativas de inclusão de arquivos locais.

```
GET https://valsec.example.com/lfi?page=../../../etc/passwd
```
- **Descrição**: Tenta incluir o arquivo de senhas do sistema

```
GET https://valsec.example.com/lfi?page=../../../proc/self/environ
```
- **Descrição**: Tenta acessar as variáveis de ambiente do processo

```
GET https://valsec.example.com/lfi?page=../../../var/log/apache2/access.log
```
- **Descrição**: Tenta incluir logs do Apache que podem conter código malicioso

### 6. Testes de API

Este teste simula o envio de um payload malicioso para uma API.

```
POST https://valsec.example.com/api/test
Content-Type: application/json

{
  "username": "admin' OR '1'='1",
  "password": "' OR '1'='1",
  "script": "<script>alert('XSS')</script>",
  "command": "rm -rf /",
  "file": "../../../etc/passwd"
}
```
- **Descrição**: Envia um payload JSON contendo múltiplos vetores de ataque

## Como Verificar se as Proteções Estão Funcionando

1. **Proteção Ativa**: Se as proteções do Cloudflare OWASP Core Ruleset estiverem funcionando corretamente, você deverá ver uma página de erro do Cloudflare (código 403) ao tentar executar estes ataques.

2. **Proteção Inativa**: Se as requisições passarem e você ver a resposta da aplicação, isso indica que as proteções não estão bloqueando os ataques como deveriam.

## Notas Importantes

- Estes testes devem ser realizados apenas em ambientes controlados e com autorização.
- O objetivo é verificar a eficácia das proteções, não explorar vulnerabilidades reais.
- Todos os endpoints implementados na aplicação são simulações e não executam realmente os comandos maliciosos.