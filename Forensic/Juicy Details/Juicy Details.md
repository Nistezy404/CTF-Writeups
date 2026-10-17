# 🔍 Juicy Details — CTF Writeup
### TryHackMe Room | Log Analysis · Reconstrução de Ataque a Partir de Logs (access.log, vsftpd.log, auth.log) — OWASP Juice Shop

---

| **Analista**          | Mauricio Robert                                                                              |
|-----------------------|----------------------------------------------------------------------------------------------|
| **Organização**       | Faculdade Impacta                                                                            |
| **Data do Relatório** | 16/10/2026                                                                                   |
| **Data do Incidente** | 11/04/2021 (09:08 – 09:42 UTC)                                                               |
| **Classificação**     | CONFIDENCIAL                                                                                 |
| **Ferramentas**       | `cat` / `grep` / `less` (terminal) — `access.log`, `vsftpd.log`, `auth.log`                  |
| **Host Analisado**    | `Plumbus` (usuário `nistezy`) — pasta `~/Transferências/logs_1618139984797`                  |
| **Aplicação alvo**    | OWASP Juice Shop (loja de e-commerce vulnerável, API REST `/rest/...`)                        |

---

## 🔍 Resumo Executivo

O desafio **Juicy Details** (TryHackMe) pede para reconstruir, a partir de três arquivos de log (`access.log`, `vsftpd.log` e `auth.log`), o ataque completo sofrido por uma instância do **OWASP Juice Shop**. O atacante (IP **`192.168.10.5`**) seguiu uma cadeia clássica: começou com um **scan de reconhecimento via Nmap**, tentou um **ataque de força bruta com Hydra** contra o endpoint de login (`/rest/user/login`), que **teve sucesso às 09:16:31 UTC**; em seguida usou o **sqlmap** para explorar uma **SQL Injection** no parâmetro **`q`** do endpoint de busca de produtos (`/rest/products/search`), confirmando a falha com um `UNION SELECT` manual via **curl** que extraiu **id, e-mail e senha** da tabela `Users`; também **raspou e-mails de usuários na seção de avaliações de produtos** (`/rest/products/<id>/reviews`); depois enumerou diretórios com **Feroxbuster**, descobrindo o endpoint **`/ftp`**, de onde tentou baixar `www-data.bak` e `coupons_2013.md.bak` via HTTP (bloqueado, 403) e, por fim, conseguiu baixar os mesmos arquivos via **FTP anônimo**; finalmente, obteve **acesso a shell via SSH** com a conta de serviço **`www-data`**. A investigação respondeu a **onze questões técnicas**.

---

## 🛠 Ferramentas Utilizadas

| Ferramenta / Comando                              | Finalidade                                                                                                  |
|-----------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| **`cat access.log`**                                | Leitura completa do log de acesso HTTP da aplicação                                                           |
| **`cat access.log \| grep -Ei 'nmap\|hydra\|sqlmap\|curl\|feroxbuster'`** | Localizar todas as requisições feitas pelas ferramentas do atacante, por User-Agent     |
| **`cat vsftpd.log`**                                | Leitura do log do serviço FTP                                                                                |
| **`cat vsftpd.log \| grep 'anonymous'`**            | Isolar tentativas/logins da conta anônima no FTP                                                             |
| **`less auth.log`** (ou `cat auth.log`)             | Leitura do log de autenticação do SSH (`sshd`)                                                               |

---

## 📋 Perguntas e Respostas

### Q1 — Quais ferramentas o atacante usou? (ordenadas pela ocorrência no log)

> **Resposta: `Nmap, Hydra, sqlmap, curl, Feroxbuster`**

**Solução:** Filtrando `access.log` pelos *User-Agents* das ferramentas mais comuns, e ordenando pelo timestamp de primeira ocorrência de cada uma:

```
09:08:34–35   "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
09:16:27–32   "Mozilla/5.0 (Hydra)"
09:29:14–17   "sqlmap/1.5.2#stable (http://sqlmap.org)"
09:32:51      "curl/7.74.0"
09:34:33      "feroxbuster/2.2.1"
```

Ou seja, na ordem cronológica em que aparecem no log: **Nmap** (reconhecimento) → **Hydra** (força bruta) → **sqlmap** (SQL Injection automatizada) → **curl** (exploração manual da SQLi) → **Feroxbuster** (enumeração de diretórios).

---

### Q2 — Qual endpoint foi vulnerável a um ataque de força bruta?

> **Resposta: `/rest/user/login`**

**Solução:** As requisições com *User-Agent* `Mozilla/5.0 (Hydra)` (09:16:27–09:16:32) são todas contra o mesmo caminho:

```
"POST /rest/user/login HTTP/1.0" 401 26 "-" "Mozilla/5.0 (Hydra)"
"GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
...
"POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"   ← sucesso
```

Dezenas de tentativas `POST` retornando **401 Unauthorized** (credencial errada), intercaladas com `GET` retornando **500** — padrão típico de força bruta de credenciais do **Hydra** contra o formulário de login da API.

---

### Q3 — Qual endpoint foi vulnerável a SQL Injection?

> **Resposta: `/rest/products/search`**

**Solução:** Todas as requisições do `sqlmap` (e do `curl`, Q8) miram o mesmo caminho:

```
"GET /rest/products/search?q=1%29%20WAITFOR%20DELAY...  HTTP/1.1" 500 - "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"
"GET /rest/products/search?q=1%27%29%20AND%20...        HTTP/1.1" 200 30 "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"
"GET /rest/products/search?q=qwert%27%29%29%20UNION%20SELECT%20id%2Cemail%2Cpassword...FROM%20Users-- HTTP/1.1" 200 3742 "-" "curl/7.74.0"
```

O endpoint de **busca de produtos** da API (`/rest/products/search`) é o ponto vulnerável — o `sqlmap` testa dezenas de payloads clássicos (`WAITFOR DELAY`, `UNION SELECT`, `ORDER BY`, `DBMS_PIPE.RECEIVE_MESSAGE`, comparações booleanas) até confirmar e explorar a injeção.

---

### Q4 — Qual parâmetro foi usado para a SQL Injection?

> **Resposta: `q`**

**Solução:** Em todas as requisições maliciosas ao endpoint de busca, o payload é injetado no parâmetro de *query string* **`q`**:

```
/rest/products/search?q=1%29%20WAITFOR%20DELAY...
/rest/products/search?q=1%27%29%20AND%20205895%3DCAST...
/rest/products/search?q=qwert%27%29%29%20UNION%20SELECT%20id%2Cemail%2Cpassword%2C...FROM%20Users--
```

O parâmetro **`q`** (de "query", usado para o termo de busca de produtos) não sanitiza a entrada do usuário antes de montá-la na consulta SQL — a clássica falha de **SQL Injection não-parametrizada**.

---

### Q5 — Qual endpoint o atacante tentou usar para recuperar arquivos? (incluindo a `/`)

> **Resposta: `/ftp`**

**Solução:** Na varredura do **Feroxbuster** (09:34:33), entre os diretórios descobertos está:

```
"GET /ftp HTTP/1.1" 200 4852 "-" "feroxbuster/2.2.1"
"GET /ftp/www-data.bak HTTP/1.1" 403 300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
"GET /ftp/coupons_2013.md.bak HTTP/1.1" 403 78965 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

O Feroxbuster encontrou o caminho **`/ftp`** (código 200), listando arquivos de um diretório exposto via HTTP; o atacante então tentou baixar arquivos diretamente dali pelo navegador, mas recebeu **403 Forbidden** nas duas tentativas — o servidor web bloqueia o acesso direto, embora revele os nomes dos arquivos.

---

### Q6 — Qual seção do site o atacante usou para raspar endereços de e-mail de usuários?

> **Resposta: Seção de avaliações de produtos — `/rest/products/<id>/reviews`**

**Solução:** Logo após o scan do Nmap, o log mostra uma sequência longa e sistemática de requisições, percorrendo quase todos os IDs de produto:

```
"GET /rest/products/3/reviews HTTP/1.1" 304 - "http://192.168.10.4/" "...Firefox/78.0"
"GET /rest/products/30/reviews HTTP/1.1" 200 187 "http://192.168.10.4/" "...Firefox/78.0"
"GET /rest/products/22/reviews HTTP/1.1" 200 177 "http://192.168.10.4/" "...Firefox/78.0"
"GET /rest/products/25/reviews HTTP/1.1" 200 30 "http://192.168.10.4/" "...Firefox/78.0"
... (produtos 5, 41, 38, 33, 17, 7, 16, 15, 18, 14, 26, 13, 19, 37, 34, 8, 29, 21, 4, 23, 32, 2, 35, 36, 9, 20 ...)
"GET /api/Feedbacks/ HTTP/1.1" 200 - "http://192.168.10.4/" "...Firefox/78.0"
```

O cabeçalho `Referer: http://192.168.10.4/` e o *User-Agent* de navegador (Firefox) mostram que essas requisições vêm da navegação normal pelo site — o atacante percorreu, um a um, as **avaliações de cada produto** (`/rest/products/<id>/reviews`), seção onde o Juice Shop expõe o e-mail do autor de cada review, e assim coletou (*scraped*) endereços de e-mail de usuários legítimos.

---

### Q7 — O ataque de força bruta foi bem-sucedido? Se sim, qual o timestamp do login bem-sucedido?

> **Resposta: `Yay`, `11/Apr/2021:09:16:31 +0000`**

**Solução:** Entre as dezenas de respostas `401` do Hydra, uma única linha se destaca com código de sucesso:

```
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"
```

**Sim (Yay)** — o ataque de força bruta teve sucesso. O `POST /rest/user/login` retornou **`200 831`** (831 bytes de corpo, compatível com um token JWT + dados do usuário autenticado), em **`11/Apr/2021:09:16:31 +0000`**, cercado de outras tentativas que continuaram retornando `401`.

---

### Q8 — Que informação de usuário o atacante conseguiu recuperar do endpoint vulnerável à SQL Injection?

> **Resposta: `id, email e password` (da tabela Users)**

**Solução:** A requisição manual feita com `curl`, após o `sqlmap` confirmar a injeção, explicita a consulta:

```
GET /rest/products/search?q=qwert%27%29%29%20UNION%20SELECT%20id%2Cemail%2Cpassword%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%2C%27%27%20FROM%20Users--
HTTP/1.1" 200 3742 "-" "curl/7.74.0"
```

Decodificando o payload: `UNION SELECT id,email,password,'','','',... FROM Users--`. A resposta veio com **200** e **3.742 bytes** — um retorno de dados considerável, consistente com múltiplos registros de usuários. O atacante conseguiu extrair, para cada conta: **`id`**, **`email`** e **`password`** (hash) da tabela `Users` do banco de dados.

---

### Q9 — Quais arquivos eles tentaram baixar do endpoint vulnerável (da questão 5)?

> **Resposta: `www-data.bak` e `coupons_2013.md.bak`**

**Solução:** Como visto na Q5, logo após o Feroxbuster encontrar `/ftp`, o atacante tentou baixar dois arquivos específicos diretamente via navegador:

```
"GET /ftp/www-data.bak HTTP/1.1" 403 300 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
"GET /ftp/coupons_2013.md.bak HTTP/1.1" 403 78965 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

Os dois arquivos — **`www-data.bak`** (um backup/credencial do usuário de serviço do servidor web) e **`coupons_2013.md.bak`** (um backup de cupons antigos) — foram bloqueados pelo servidor HTTP (**403**), mas o atacante já sabia exatamente o que buscar, o que indica que esses nomes vieram da listagem do diretório `/ftp` (Q5) ou de um `ls` anterior no FTP.

---

### Q10 — Qual serviço e nome de conta foram usados para recuperar os arquivos da questão anterior? (serviço, usuário)

> **Resposta: `FTP, anonymous`**

**Solução:** Como o acesso via HTTP foi bloqueado, o atacante foi direto ao serviço de **FTP**. Em `vsftpd.log`:

```
Sun Apr 11 08:15:58 2021 [pid 6526] [ftp] OK LOGIN: Client "::ffff:127.0.0.1", anon password "?"
Sun Apr 11 08:18:04 2021 [pid 6628] CONNECT: Client "::ffff:127.0.0.1"
Sun Apr 11 08:18:07 2021 [pid 6627] [ftp] OK LOGIN: Client "::ffff:127.0.0.1", anon password "ls"
...
Sun Apr 11 09:35:32 2021 [pid 8153] CONNECT: Client "::ffff:192.168.10.5"
Sun Apr 11 09:35:37 2021 [pid 8152] [ftp] OK LOGIN: Client "::ffff:192.168.10.5", anon password "?"
Sun Apr 11 09:35:45 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/www-data.bak", 2602 bytes, 544.81Kbyte/sec
Sun Apr 11 09:36:08 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/coupons_2013.md.bak", 131 bytes, 3.01Kbyte/sec
```

Todos os logins, inclusive os bem-sucedidos, mostram usuário **`anon`** (o `vsftpd` identifica o login anônimo com o rótulo `anon`, correspondente à conta **`anonymous`** do protocolo FTP) — o "password" trocado (`?`, `ls`, `IEUser@`) é apenas o e-mail/comentário que clientes FTP anônimos enviam como senha, não uma credencial real. O serviço é **FTP** e o usuário é **`anonymous`**. Os downloads de `www-data.bak` (2.602 bytes) e `coupons_2013.md.bak` (131 bytes) confirmam a questão anterior.

---

### Q11 — Qual serviço e usuário foram usados para obter acesso a shell no servidor? (serviço, usuário)

> **Resposta: `SSH, www-data`**

**Solução:** Em `auth.log`, após uma sequência de falhas de autenticação do `sshd` contra a conta `www-data` (ataque de força bruta via SSH, portas efêmeras 40072–40114, todas de `192.168.10.5`):

```
Apr 11 09:39:51 thunt sshd[8229]: Failed password for www-data from 192.168.10.5 port 40078 ssh2
...
Apr 11 09:39:52 thunt sshd[8232]: error: maximum authentication attempts exceeded for www-data from 192.168.10.5 port 40084 ssh2 [preauth]
Apr 11 09:39:52 thunt sshd[8232]: Disconnecting authenticating user www-data 192.168.10.5 port 40084: Too many authentication failures [preauth]
...
Apr 11 09:41:19 thunt sshd[8260]: Accepted password for www-data from 192.168.10.5 port 40112 ssh2
Apr 11 09:41:19 thunt sshd[8260]: pam_unix(sshd:session): session opened for user www-data by (uid=0)
Apr 11 09:41:19 thunt systemd-logind[737]: New session 12 of user www-data.
...
Apr 11 09:41:32 thunt sshd[8494]: Accepted password for www-data from 192.168.10.5 port 40114 ssh2
Apr 11 09:41:32 thunt sshd[8494]: pam_unix(sshd:session): session opened for user www-data by (uid=0)
Apr 11 09:42:57 thunt su: pam_unix(su:session): session closed for user www-data
```

Depois de múltiplas falhas e desconexões por excesso de tentativas, o `sshd` finalmente registra **`Accepted password for www-data`** às **09:41:19** (sessão 12) e novamente às **09:41:32** (sessão 14) — login bem-sucedido via **SSH** com a conta de serviço **`www-data`**, provavelmente usando a senha extraída de `www-data.bak` (Q9/Q10). Há ainda um comando `su` registrado, indicando possível tentativa de escalonamento de privilégios a partir dessa shell.

---

## ⛓ Kill Chain — Cadeia de Ataque Reconstruída

```
[FASE 1 — RECONHECIMENTO]  (09:08:34–35)
    Nmap Scripting Engine (NSE): POST/PROPFIND/GET em várias rotas
    .git/HEAD, /sdk, checagens de maiúsculas/minúsculas, /nmap/folder/check...
    ↓
[FASE 2 — FORÇA BRUTA NO LOGIN]  (09:16:27–32)
    Hydra → POST /rest/user/login (dezenas de tentativas, 401)
    09:16:31 → POST /rest/user/login  200 831  ✔ SUCESSO
    ↓
[FASE 3 — COLETA DE E-MAILS (SCRAPING)]
    Navegação sistemática por /rest/products/<id>/reviews (IDs 2–41)
    + /api/Feedbacks/ → e-mails de autores de reviews coletados
    ↓
[FASE 4 — SQL INJECTION AUTOMATIZADA]  (09:29:14–17)
    sqlmap → /rest/products/search?q=...
    Testes: WAITFOR DELAY, booleanas (CAST/CONVERT), UNION, ORDER BY,
            DBMS_PIPE.RECEIVE_MESSAGE, extração por XMLType/UPPER
    ↓
[FASE 5 — EXPLORAÇÃO MANUAL DA SQLI]  (09:32:51)
    curl → UNION SELECT id,email,password,... FROM Users--
    200 OK, 3742 bytes → vazamento de credenciais de usuários
    ↓
[FASE 6 — ENUMERAÇÃO DE DIRETÓRIOS]  (09:34:33)
    Feroxbuster → /api, /administartion, /login, /admin, /backup,
                  /promotion, /ftp (200, 4852 bytes)
    ↓
[FASE 7 — TENTATIVA DE DOWNLOAD VIA HTTP]  (09:34:40–43)
    GET /ftp/www-data.bak           → 403 Forbidden
    GET /ftp/coupons_2013.md.bak    → 403 Forbidden
    ↓
[FASE 8 — PIVÔ PARA FTP ANÔNIMO]  (09:35:32–09:36:08)
    Login anônimo (anon) bem-sucedido
    DOWNLOAD /www-data.bak          (2602 bytes)
    DOWNLOAD /coupons_2013.md.bak   (131 bytes)
    ↓
[FASE 9 — FORÇA BRUTA + ACESSO VIA SSH]  (09:39:51–09:41:32)
    Múltiplas falhas "Failed password for www-data" (ssh2)
    09:41:19 → Accepted password for www-data  ✔ SHELL OBTIDA
    09:41:32 → 2ª sessão aceita para www-data
    09:42:57 → comando su executado (possível escalonamento)
```

---

## 🗺 Mapeamento Investigativo

| Pergunta | Fonte de Evidência | Artefato |
|----------|--------------------|----------|
| Ferramentas usadas (ordem) | `access.log` — User-Agents filtrados | `Nmap, Hydra, sqlmap, curl, Feroxbuster` |
| Endpoint de força bruta | `access.log` — requisições do Hydra | `/rest/user/login` |
| Endpoint de SQLi | `access.log` — requisições do sqlmap/curl | `/rest/products/search` |
| Parâmetro da SQLi | `access.log` — query string | `q` |
| Endpoint de recuperação de arquivos | `access.log` — Feroxbuster | `/ftp` |
| Seção de scraping de e-mails | `access.log` — navegação por produto | `/rest/products/<id>/reviews` |
| Sucesso da força bruta | `access.log` — linha `200 831` do Hydra | `Yay`, `11/Apr/2021:09:16:31 +0000` |
| Dados vazados pela SQLi | `access.log` — payload do `curl` | `id, email, password` |
| Arquivos visados no `/ftp` | `access.log` — tentativas `403` | `www-data.bak, coupons_2013.md.bak` |
| Serviço/usuário dos downloads | `vsftpd.log` | `FTP, anonymous` |
| Serviço/usuário da shell | `auth.log` (sshd) | `SSH, www-data` |

---

## 🚨 Artefatos e Indicadores Identificados (IOCs)

| Tipo | Indicador | Contexto |
|------|-----------|----------|
| IP (atacante) | `192.168.10.5` | Origem de todas as ferramentas e ataques |
| Host (vítima) | `thunt` / app em `192.168.10.4` | Servidor do Juice Shop + FTP + SSH |
| Endpoint | `/rest/user/login` | Alvo da força bruta (Hydra) |
| Endpoint | `/rest/products/search?q=` | Alvo da SQL Injection |
| Endpoint | `/rest/products/<id>/reviews`, `/api/Feedbacks/` | Scraping de e-mails de usuários |
| Endpoint | `/ftp` | Diretório exposto via HTTP, descoberto pelo Feroxbuster |
| Arquivo | `www-data.bak` (2.602 bytes) | Backup com credenciais da conta de serviço `www-data` |
| Arquivo | `coupons_2013.md.bak` (131 bytes) | Backup de cupons |
| Query maliciosa | `UNION SELECT id,email,password,... FROM Users--` | Extração de credenciais via SQLi |
| Credencial comprometida | `www-data` (senha extraída do backup) | Usada para login SSH bem-sucedido |
| Timestamp | `11/Apr/2021 09:16:31 UTC` | Login bem-sucedido via força bruta (Hydra) |
| Timestamp | `11/Apr/2021 09:35:45 / 09:36:08 UTC` | Downloads via FTP anônimo |
| Timestamp | `11/Apr/2021 09:41:19 / 09:41:32 UTC` | Login SSH bem-sucedido como `www-data` |
| Ferramenta | Nmap (NSE) | Reconhecimento inicial |
| Ferramenta | Hydra | Força bruta de login |
| Ferramenta | sqlmap 1.5.2 | Exploração automatizada de SQLi |
| Ferramenta | curl 7.74.0 | Exploração manual da SQLi |
| Ferramenta | Feroxbuster 2.2.1 | Enumeração de diretórios/endpoints |
| Técnica (MITRE ATT&CK) | `T1595.002` | Active Scanning: Vulnerability Scanning (Nmap) |
| Técnica (MITRE ATT&CK) | `T1110.001` | Brute Force: Password Guessing (Hydra) |
| Técnica (MITRE ATT&CK) | `T1190` | Exploit Public-Facing Application (SQL Injection) |
| Técnica (MITRE ATT&CK) | `T1213` | Data from Information Repositories (scraping de reviews) |
| Técnica (MITRE ATT&CK) | `T1555` | Credentials from Password Stores (`www-data.bak`) |
| Técnica (MITRE ATT&CK) | `T1078` | Valid Accounts (FTP anônimo, SSH com `www-data`) |

---

## ✅ Resumo das Flags

| # | Pergunta | Flag / Resposta |
|---|----------|------------------|
| Q1 | Ferramentas usadas (ordem de ocorrência) | `Nmap, Hydra, sqlmap, curl, Feroxbuster` |
| Q2 | Endpoint vulnerável a força bruta | `/rest/user/login` |
| Q3 | Endpoint vulnerável a SQL Injection | `/rest/products/search` |
| Q4 | Parâmetro usado na SQLi | `q` |
| Q5 | Endpoint usado para recuperar arquivos | `/ftp` |
| Q6 | Seção usada para raspar e-mails | Avaliações de produtos — `/rest/products/<id>/reviews` |
| Q7 | Força bruta bem-sucedida? | `Yay`, `11/Apr/2021:09:16:31 +0000` |
| Q8 | Dados recuperados via SQLi | `id, email, password` |
| Q9 | Arquivos visados no `/ftp` | `www-data.bak, coupons_2013.md.bak` |
| Q10 | Serviço/usuário dos downloads | `FTP, anonymous` |
| Q11 | Serviço/usuário da shell | `SSH, www-data` |

---

## 📚 Referências

- [TryHackMe — Juicy Details](https://tryhackme.com/room/juicydetails)
- [OWASP Juice Shop — Documentação](https://pwning.owasp-juice.shop/)
- [sqlmap — Documentação oficial](https://sqlmap.org/)
- [THC-Hydra — GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Feroxbuster — GitHub](https://github.com/epi052/feroxbuster)
- [vsftpd — Log Format Documentation](https://security.appspot.com/vsftpd.html)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [MITRE ATT&CK — T1555 Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)

---