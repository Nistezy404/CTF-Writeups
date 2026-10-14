# 🔍 Invite Only — CTF Writeup
### TryHackMe Room | Threat Intelligence · Análise de IOCs (VirusTotal Offline) — Discord Invite Hijacking → ClickFix → AsyncRAT / Skuld Stealer

---

| **Analista**          | Mauricio Robert                                                                              |
|-----------------------|----------------------------------------------------------------------------------------------|
| **Organização**       | Faculdade Impacta                                                                            |
| **Data do Relatório** | 11/10/2026                                                                                   |
| **Data do Incidente (campanha)** | Fevereiro–Julho/2025 (conforme datas dos artefatos no VirusTotal)                 |
| **Classificação**     | CONFIDENCIAL                                                                                 |
| **Ferramentas**       | VirusTotal Offline (ambiente do lab) · Google Search · Check Point Research                  |
| **Campanha**          | "Discord Invite Hijacking" / "From Trust to Threat" — cadeia ClickFix → AsyncRAT + Skuld Stealer |

---

## 🔍 Resumo Executivo

O desafio **Invite Only** (TryHackMe) parte de um hash SHA-256 sinalizado como malicioso e pede para reconstruir, a partir de relações do VirusTotal, toda a cadeia de entrega de um malware. O arquivo sinalizado é **`syshelpers.exe`** (Win32 EXE, 214 KB, 51/72 motores — classificação `trojan.tedy/fxnp`). Seus **dois pais de execução** são, em ordem cronológica, um script **PowerShell** (`361GJX7J`, detectado 08/05/2025) e o executável **`installer.exe`** (detectado 01/06/2025) — o mesmo `installer.exe` que, por sua vez, **dropa de volta o `syshelpers.exe`**, fechando um laço de reinfecção (daí o nome da sala, *"convite" que se repete*). O `syshelpers.exe` também dropa **`AClient.exe`**. Investigando o IP relacionado **`101.99.76.120`**, a comunidade do VirusTotal identifica um **C2 do AsyncRAT** na porta 7707 e referencia dois relatórios públicos — um deles, da **Check Point Research** (*"From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery"*, 12/06/2025), descreve a campanha completa: atacantes sequestram **convites expirados do Discord**, redirecionam vítimas para sites de phishing que usam a técnica **ClickFix**, entregam um downloader PowerShell hospedado no **Pastebin**, e distribuem o RAT **AsyncRAT** e um **Skuld Stealer** customizado (focado em carteiras cripto), usando ferramentas como **ChromeKatz** para roubar cookies do Chrome mesmo com o App-Bound Encryption. A investigação respondeu a **dez questões técnicas**.

---

## 🛠 Ferramentas Utilizadas

| Ferramenta                              | Finalidade                                                                                                       |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| **VirusTotal Offline** (ambiente do lab) | Consulta de hashes por abas **Detection**, **Details**, **Relations**, **Behavior** e **Community**              |
| **Relations → Execution Parents / Dropped Files** | Reconstrução da cadeia de execução entre `installer.exe` ↔ `syshelpers.exe` ↔ `AClient.exe`             |
| **Relations → Contacted IPs**           | Identificação do IP de C2 `101.99.76.120`                                                                        |
| **Community (comentários)**             | Atribuição de família de malware (AsyncRAT) e referências a relatórios públicos                                  |
| **Google Search**                       | Localização do relatório original da Check Point Research                                                        |
| **Check Point Research (artigo)**       | Leitura do relatório *"From Trust to Threat..."* — técnica ClickFix, ferramenta ChromeKatz, plataforma Discord   |

---

## 📋 Perguntas e Respostas

### Q1 — Qual é o nome do arquivo identificado com o hash SHA-256 sinalizado?

> **Resposta: `syshelpers.exe`**

**Solução:** Consultando o hash sinalizado `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f` no VirusTotal, o cabeçalho do relatório mostra:

```
51   Threat Detection          51/72 vendors flagged as malicious
File: syshelpers.exe  (Win32 EXE • 214.0 KB)
Classification: trojan.tedy/fxnp  (tags: trojan, downloader)
Last analyzed: 2025-07-23 11:20:06
```

O nome do arquivo é **`syshelpers.exe`** — um nome deliberadamente genérico ("ajudantes do sistema"), típico de técnica de *masquerading* para passar despercebido em uma lista de processos.

---

### Q2 — Qual é o tipo de arquivo associado ao hash sinalizado?

> **Resposta: `Win32 EXE`**

**Solução:** O mesmo cabeçalho do relatório do VirusTotal identifica o tipo de arquivo e seu tamanho:

```
File        syshelpers.exe
            Win32 EXE • 214.0 KB
```

É um executável PE de 32 bits para Windows, com 51 de 72 motores de antivírus classificando-o como malicioso.

---

### Q3 — Quais são os pais de execução (execution parents) do hash sinalizado? Liste os nomes cronologicamente, separados por vírgula. Anote os hashes para uso posterior.

> **Resposta: `361GJX7J, installer.exe`**

**Solução:** Na aba **Relations** de `syshelpers.exe`, o painel **Execution Parents (2)** lista:

```
2025-05-08 18:20:56   Powershell • 361GJX7J   (15/62)
hash: 047c5eec0445746862710d20e50a5dd04510b7e625fa5c1f5d48ce078001c0de

2025-06-01 18:49:58   Win32 EXE  • installer.exe   (24/72)
hash: fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942
```

Ordenando **cronologicamente** pela data de primeira detecção: o script **PowerShell `361GJX7J`** (08/05/2025) vem antes do **`installer.exe`** (01/06/2025). Ou seja, a cadeia real de infecção é: PowerShell → `installer.exe` → `syshelpers.exe` → (`AClient.exe`).

**Hashes anotados para uso posterior:**

| Arquivo | SHA-256 |
|---|---|
| PowerShell `361GJX7J` | `047c5eec0445746862710d20e50a5dd04510b7e625fa5c1f5d48ce078001c0de` |
| `installer.exe` | `fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942` |

---

### Q4 — Qual é o nome do arquivo que está sendo dropado? Anote o valor do hash para uso posterior.

> **Resposta: `AClient.exe`**

**Solução:** Ainda na aba **Relations** de `syshelpers.exe`, o painel **Dropped Files (1)** mostra:

```
2025-04-15 16:21:47
unknown • AClient.exe
hash: dd02c105809e4ca41a5489e585ba025eddb89a91703b73a566c9903e6406a08c
```

O `syshelpers.exe` dropa o arquivo **`AClient.exe`** (tipo "unknown" no VT, 0 detecções no momento da captura). Esse nome é usado por clientes legítimos de acesso remoto (como AnyDesk) — outra pista de *masquerading*, coerente com o perfil de RAT da campanha.

**Hash anotado:** `dd02c105809e4ca41a5489e585ba025eddb89a91703b73a566c9903e6406a08c`

---

### Q5 — Pesquise o segundo hash da questão 3 e liste os quatro arquivos maliciosos dropados, na ordem em que aparecem (de cima para baixo), separados por vírgula.

> **Resposta: `searchHost.exe, syshelpers.exe, nat1.vbs, runsys.vbs`**

**Solução:** O segundo hash da Q3 (cronologicamente) é o do **`installer.exe`** — `fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942`. Sua aba **Relations** mostra o painel **Dropped Files (20)**. Rolando a lista, os itens que aparecem com o triângulo de alerta (⚠️ malicioso) são, na ordem de exibição:

```
2025-03-17 19:58:35   Win32 EXE • searchHost.exe   ⚠️ 37/73
   59feea18dc45bbe2b9798c9549983d79cc4788a90dafe2b0a930c60c7d2d6d7

2025-07-23 11:20:06   Win32 EXE • syshelpers.exe    ⚠️ 51/72
   5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f

2025-02-28 08:56:57   VBA      • nat1.vbs           ⚠️ 1/60
   87be7b4336367083ca9fcb1c7b9d0459659f2ffafde51f7236960f6032512409

2025-06-26 12:24:05   VBA      • runsys.vbs         ⚠️ 2/62
   cb567a26c9aa7b023bd713756035530e56330ea87c3adbd26c83a5c8dc1cf9b9
```

Entre eles, aparecem itens **sem** alerta (✅, limpos ou sem detecção): `gcsnn1nn.dll` (Win32 DLL), `browsers.zip` (ZIP) e um script `_PSScriptPolicyTest_qn3agocm.taa.ps1` (PowerShell) — esses não contam como "maliciosos" pelo critério do desafio. Confirmando o laço da sala: o próprio **`syshelpers.exe`** (nosso hash sinalizado na Q1) é um dos arquivos dropados pelo `installer.exe` — um "convite" (infecção) que se repete.

---

### Q6 — Analise os arquivos relacionados ao IP sinalizado. Qual é a família de malware que liga esses arquivos?

> **Resposta: `AsyncRAT`**

**Solução:** Entre os **Contacted IPs** dos relatórios anteriores está o IP **`101.99.76.120`**. Pesquisando-o no VirusTotal, a aba **Community** traz comentários de pesquisadores de ameaças confirmando a atribuição:

```
NIXLovesXerneas (1 ano atrás):
"AsyncRAT C2 at 101.99.76.120:7707
 Geolocation: Lelystad, Flevoland
 Organization: Shinjiru Technology Sdn Bhd
 ASN: AS45839 | Country: NL
 Confidence Level: 75
 IOC: https://threatfox.abuse.ch/ioc/1423990/
 #NL #AS45839"

paul_melson (1 ano atrás):
"#StagedC2 config observed at Sat Feb 15 14:41:06 2025 UTC,
 located at https://pastebin.com/raw/QdseGsQL  C2: 101.99.76.120:6606"

paul_melson (1 ano atrás):
"#StagedC2 config observed at Thu Feb 13 20:03:03 2025 UTC,
 located at https://pastebin.com/raw/Y6QD7D2h  C2: 101.99.76.120:8808"
```

O IP é reportado como C2 em **múltiplas portas** (6606, 7707, 8808), um padrão comum de **AsyncRAT**, que costuma trocar de porta entre builds/campanhas. A família que liga `installer.exe`, `syshelpers.exe` e `AClient.exe` a esse IP é, portanto, **AsyncRAT**.

---

### Q7 — Qual é o título do relatório original onde esses indicadores sinalizados são mencionados? Use o Google para encontrar o relatório.

> **Resposta: `From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery`**

**Solução:** O mesmo painel de comentários do IP `101.99.76.120` referencia dois relatórios:

```
rectifyq (1 ano atrás):
Title: Discord Invite Hijacking: How Fake Links Are Delivering Infostealers
Date: 2025-06-20
References: https://darkatlas.io/blog/discord-invite-hijacking-how-fake-links-are-delivering-infostealers

rectifyq (1 ano atrás):
IOC Context: AsyncRAT C2
Title: From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery
Date: 2025-06-12
References: https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery
```

Pesquisando no Google por esse título, o resultado aponta para o blog da **Check Point Research**, publicado em **12/06/2025**:

```
FROM TRUST TO THREAT: HIJACKED DISCORD INVITES USED FOR MULTI-STAGE MALWARE DELIVERY
research.checkpoint.com — June 12, 2025
```

Esse é o relatório original ("IOC Context: AsyncRAT C2") que documenta a campanha e os indicadores sinalizados no desafio.

---

### Q8 — Qual ferramenta os atacantes usaram para roubar cookies do navegador Google Chrome?

> **Resposta: `ChromeKatz`**

**Solução:** O artigo da Check Point Research lista, em **Key Takeaways**:

```
• The operation continues to evolve, and threat actors can now bypass Chrome's
  App Bound Encryption (ABE) by using adapted tools like ChromeKatz to steal
  cookies from new Chromium browser versions.
```

A ferramenta **ChromeKatz** foi adaptada pelos atacantes para contornar o **App-Bound Encryption (ABE)** do Chrome — a proteção introduzida pelo Google para dificultar o roubo de cookies/credenciais por malware — e assim extrair cookies de sessão mesmo em versões recentes do navegador.

---

### Q9 — Qual técnica de phishing os atacantes usaram? Use o relatório para responder.

> **Resposta: `ClickFix`**

**Solução:** O mesmo relatório descreve, também em **Key Takeaways**:

```
• The attackers combined the ClickFix phishing technique, multi-stage loaders,
  and time-based evasions to stealthily deliver AsyncRAT, and a customized
  Skuld Stealer targeting crypto wallets.
```

O artigo detalha a mecânica da técnica (**Figura 9** — *"Social engineering technique tricking a user to execute a malicious command"*): a vítima é instruída a pressionar **Ctrl+V** para "colar um código de verificação" e depois **Enter** para "se autenticar" — mas na prática isso cola e executa um comando que baixa e roda um script **PowerShell** hospedado no Pastebin (`https://pastebin[.]com/raw/zW0L2z2M`). É a técnica **ClickFix** (também conhecida por enganar o usuário a executar comandos via "verificação falsa" de captcha/CAPTCHA ou Discord).

---

### Q10 — Qual é o nome da plataforma usada para redirecionar o usuário para servidores maliciosos?

> **Resposta: `Discord`**

**Solução:** O diagrama de cadeia de infecção do relatório (**Figura 10** — *"Infection chain overview: From hijacked Discord invite to execution of PowerShell downloader"*) mostra:

```
Legitimate Website
   │ Links
   ▼
Hijacked Discord Invite Link
   │ Redirects
   ▼
Malicious Discord Server
   │ Redirects
   ▼
Phishing Website  →  captchaguard[.]me
   │ ClickFix
   ▼
PowerShell Command
   │ Runs
   ▼
PowerShell Downloader  →  pastebin[.]com/raw/zW0L2z2M
```

A plataforma abusada para o **redirecionamento inicial** é o **Discord**: os atacantes sequestram convites **expirados ou excluídos** (via registro de "vanity link"), fazendo com que links antigos — publicados em sites, fóruns ou redes sociais confiáveis — levem silenciosamente a um **servidor Discord malicioso** controlado pelo atacante, que então redireciona a vítima ao site de phishing.

---

## ⛓ Kill Chain — Cadeia de Entrega do Malware

```
[FASE 1 — SEQUESTRO DO CONVITE]
    Convite expirado/excluído do Discord → registrado como "vanity link" pelo atacante
    Link antigo e confiável → redireciona para servidor Discord malicioso
    ↓
[FASE 2 — PHISHING / CLICKFIX]  (site: captchaguard[.]me)
    Vítima instruída a pressionar Ctrl+V (colar) e Enter ("verificação")
    Na prática: executa um comando que baixa e roda PowerShell
    ↓
[FASE 3 — DOWNLOADER POWERSHELL]  (08/05/2025)
    Script PowerShell "361GJX7J" (hash 047c5eec...078001c0de)
    Hospedado via Pastebin (https://pastebin[.]com/raw/zW0L2z2M)
    ↓
[FASE 4 — INSTALLER]  (01/06/2025)
    installer.exe (fa102d4e3c...fc39033942)
    Dropa: searchHost.exe, syshelpers.exe, nat1.vbs, runsys.vbs (+ outros)
    ↓
[FASE 5 — LOADER SECUNDÁRIO]  (23/07/2025)
    syshelpers.exe (5d0509f68a...e39c874f) — trojan.tedy/fxnp
    Dropa: AClient.exe (dd02c105809e...6406a08c)
    Contacta: bbuseruploads.s3.amazonaws.com, bitbucket.org, s3-1-w.amazonaws.com...
    ↓
[FASE 6 — C2 / PAYLOAD FINAL]
    C2: 101.99.76.120 (portas 6606, 7707, 8808) — AsyncRAT
    Payload adicional: Skuld Stealer (carteiras cripto)
    Roubo de cookies: ChromeKatz (bypass do Chrome App-Bound Encryption)
    Exfiltração via GitHub, Bitbucket, Pastebin e Discord (tráfego "confiável")
```

---

## 🗺 Mapeamento Investigativo

| Pergunta | Fonte de Evidência | Artefato |
|----------|--------------------|----------|
| Nome do arquivo sinalizado | VT — cabeçalho do relatório (`5d0509f68a...e39c874f`) | `syshelpers.exe` |
| Tipo do arquivo sinalizado | VT — cabeçalho do relatório | `Win32 EXE` |
| Pais de execução (cronológico) | VT → Relations → Execution Parents (2) | `361GJX7J, installer.exe` |
| Arquivo dropado pelo sinalizado | VT → Relations → Dropped Files (1) | `AClient.exe` |
| 4 arquivos maliciosos do 2º hash | VT → Relations de `installer.exe` → Dropped Files (20) | `searchHost.exe, syshelpers.exe, nat1.vbs, runsys.vbs` |
| Família de malware do IP | VT → IP `101.99.76.120` → Community | `AsyncRAT` |
| Relatório original | Comentário da Community + Google Search | *From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery* |
| Ferramenta de roubo de cookies | Relatório Check Point — Key Takeaways | `ChromeKatz` |
| Técnica de phishing | Relatório Check Point — Key Takeaways + Figura 9 | `ClickFix` |
| Plataforma de redirecionamento | Relatório Check Point — Figura 10 (diagrama) | `Discord` |

---

## 🚨 Artefatos e Indicadores Identificados (IOCs)

| Tipo | Indicador | Contexto |
|------|-----------|----------|
| Hash (SHA-256) | `5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f` | `syshelpers.exe` — trojan.tedy/fxnp, 51/72 |
| Hash (SHA-256) | `fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942` | `installer.exe` — 24/72, pai de execução de `syshelpers.exe` |
| Hash (SHA-256) | `047c5eec0445746862710d20e50a5dd04510b7e625fa5c1f5d48ce078001c0de` | Powershell `361GJX7J` — 15/62, downloader inicial |
| Hash (SHA-256) | `dd02c105809e4ca41a5489e585ba025eddb89a91703b73a566c9903e6406a08c` | `AClient.exe` — dropado por `syshelpers.exe` |
| Hash (SHA-256) | `59feea18dc45bbe2b9798c9549983d79cc4788a90dafe2b0a930c60c7d2d6d7` | `searchHost.exe` — 37/73 |
| Hash (SHA-256) | `87be7b4336367083ca9fcb1c7b9d0459659f2ffafde51f7236960f6032512409` | `nat1.vbs` — 1/60 |
| Hash (SHA-256) | `cb567a26c9aa7b023bd713756035530e56330ea87c3adbd26c83a5c8dc1cf9b9` | `runsys.vbs` — 2/62 |
| IP (C2) | `101.99.76.120` | AsyncRAT C2 — portas 6606, 7707, 8808 (Shinjiru Technology Sdn Bhd, NL, AS45839) |
| URL (downloader) | `https://pastebin[.]com/raw/zW0L2z2M` | Script PowerShell malicioso hospedado no Pastebin |
| Domínio (phishing) | `captchaguard[.]me` | Site de phishing com a técnica ClickFix |
| Domínios (infraestrutura) | `bbuseruploads.s3.amazonaws.com`, `bitbucket.org`, `s3-1-w.amazonaws.com`, `res.public.onecdn.static.microsoft` | Hospedagem/entrega de payloads via serviços confiáveis |
| Ferramenta | `ChromeKatz` | Roubo de cookies — bypass do Chrome App-Bound Encryption |
| Técnica | `ClickFix` | Engenharia social — "cole e execute" via Ctrl+V/Enter |
| Plataforma abusada | `Discord` | Sequestro de convites expirados/excluídos (vanity link) |
| Família de malware | `AsyncRAT` | RAT de acesso remoto — C2 em `101.99.76.120` |
| Família de malware | `Skuld Stealer` (customizado) | Infostealer voltado a carteiras de criptomoedas |
| Referência | https://darkatlas.io/blog/discord-invite-hijacking-how-fake-links-are-delivering-infostealers | Relatório complementar (DarkAtlas, 20/06/2025) |
| Referência | https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/ | Relatório original (Check Point Research, 12/06/2025) |
| Técnica (MITRE ATT&CK) | `T1566.002` | Phishing: Spearphishing Link (convites sequestrados do Discord) |
| Técnica (MITRE ATT&CK) | `T1204.001` | User Execution: Malicious Link / ClickFix |
| Técnica (MITRE ATT&CK) | `T1059.001` | Command and Scripting Interpreter: PowerShell |
| Técnica (MITRE ATT&CK) | `T1105` | Ingress Tool Transfer (Pastebin, GitHub, Bitbucket) |
| Técnica (MITRE ATT&CK) | `T1539` | Steal Web Session Cookie (ChromeKatz) |
| Técnica (MITRE ATT&CK) | `T1102` | Web Service (uso de serviços legítimos para C2/exfiltração) |

---

## ✅ Resumo das Flags

| # | Pergunta | Flag / Resposta |
|---|----------|------------------|
| Q1 | Nome do arquivo com hash sinalizado | `syshelpers.exe` |
| Q2 | Tipo do arquivo sinalizado | `Win32 EXE` |
| Q3 | Pais de execução (cronológico) | `361GJX7J, installer.exe` |
| Q4 | Nome do arquivo dropado | `AClient.exe` |
| Q5 | 4 arquivos maliciosos dropados (ordem de exibição) | `searchHost.exe, syshelpers.exe, nat1.vbs, runsys.vbs` |
| Q6 | Família de malware ligada ao IP | `AsyncRAT` |
| Q7 | Título do relatório original | `From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery` |
| Q8 | Ferramenta de roubo de cookies do Chrome | `ChromeKatz` |
| Q9 | Técnica de phishing usada | `ClickFix` |
| Q10 | Plataforma usada para redirecionamento | `Discord` |

---

## 📚 Referências

- [TryHackMe — Invite Only](https://tryhackme.com/room/inviteonly)
- [Check Point Research — From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery (12/06/2025)](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [DarkAtlas — Discord Invite Hijacking: How Fake Links Are Delivering Infostealers (20/06/2025)](https://darkatlas.io/blog/discord-invite-hijacking-how-fake-links-are-delivering-infostealers)
- [ThreatFox (abuse.ch) — IOC 1423990 (AsyncRAT C2 101.99.76.120)](https://threatfox.abuse.ch/ioc/1423990/)
- [VirusTotal — File/IP Relations documentation](https://docs.virustotal.com/)
- [MITRE ATT&CK — T1566.002 Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK — T1539 Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK — S0129 AsyncRAT](https://attack.mitre.org/software/S0129/)

---