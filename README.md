# headercheck

[![CI](https://github.com/omarsaidiA/headerchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/omarsaidiA/headerchecker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB)

Outil en ligne de commande qui audite la configuration de sécurité HTTP d'une application web ou
d'une API : en-têtes de sécurité, cookies et politique CORS. Il produit un rapport texte, JSON ou
**SARIF** (onglet *Security* de GitHub), et son code de sortie permet de bloquer un pipeline CI.

Aucune dépendance à l'exécution : uniquement la bibliothèque standard de Python. Un outil qui
tourne dans des pipelines ne doit pas ajouter de risque de chaîne d'approvisionnement.

## Exemple

```console
$ headercheck https://api.example.com/
https://api.example.com/ (HTTP 200)
  HIGH   CORS-REFLECTED-CREDENTIALS: CORS reflects any origin and allows credentials
         untrusted origin https://headercheck.invalid accepted; Access-Control-Allow-Origin: https://headercheck.invalid (credentials: true)
         fix: Allow only an explicit list of trusted origins; any site can currently read authenticated responses.
  MEDIUM CSP-UNSAFE-INLINE: Content-Security-Policy allows inline scripts
         'self' 'unsafe-inline'
         fix: Remove 'unsafe-inline' from script-src, or use nonces or hashes instead.
$ echo $?
1
```

## Contrôles

| Domaine | Règles | Ce qui est vérifié |
|---|---|---|
| Transport | `PLAIN-HTTP`, `HSTS-MISSING`, `HSTS-INVALID`, `HSTS-SHORT` | HTTPS, présence de HSTS et `max-age` d'au moins 180 jours |
| CSP | `CSP-MISSING`, `CSP-NO-SCRIPT-RESTRICTION`, `CSP-UNSAFE-INLINE`, `CSP-UNSAFE-EVAL`, `CSP-WILDCARD-SCRIPT` | Les sources de scripts (`script-src`, sinon `default-src`) ; `'unsafe-inline'` est ignoré s'il y a un nonce ou un hash, comme dans les navigateurs |
| Clickjacking | `CLICKJACKING` | CSP `frame-ancestors` ou `X-Frame-Options: DENY/SAMEORIGIN` |
| En-têtes divers | `XCTO-MISSING`, `REFERRER-MISSING`, `REFERRER-UNSAFE`, `VERSION-DISCLOSURE` | `nosniff`, `Referrer-Policy`, versions dans `Server` et `X-Powered-By` |
| Cookies | `COOKIE-NO-SECURE`, `COOKIE-NO-HTTPONLY`, `COOKIE-NO-SAMESITE`, `COOKIE-SAMESITE-NONE-INSECURE` | Attributs de chaque `Set-Cookie` |
| CORS | `CORS-REFLECTED-CREDENTIALS`, `CORS-REFLECTED`, `CORS-NULL-ORIGIN`, `CORS-WILDCARD-CREDENTIALS`, `CORS-WILDCARD` | La requête envoie une origine non fiable (`--origin`) ; si elle est renvoyée dans `Access-Control-Allow-Origin`, n'importe quel site peut lire les réponses |

La sévérité de chaque règle est fixée dans [`rules.py`](src/headercheck/rules.py), avec la
correction recommandée.

## Choix de conception

- **Les redirections ne sont pas suivies** : on analyse la réponse de l'URL demandée. Sinon, un
  `http://` qui redirige vers `https://` serait jugé sur la réponse finale.
- **Les réponses 4xx et 5xx sont analysées** : une page 401 ou 500 doit aussi avoir ses en-têtes de
  sécurité.
- **Seuls `http` et `https` sont acceptés**, car `urllib` ouvrirait aussi `file://` ou `ftp://`.
- **SARIF et GitHub** : le *code scanning* de GitHub n'accepte que des emplacements qui sont des
  fichiers du dépôt, pas des URL. L'option `--sarif-artifact` rattache chaque résultat à un fichier
  (par exemple le contrat OpenAPI) et garde l'URL dans le message.

## Installation et utilisation

```bash
pip install git+https://github.com/omarsaidiA/headerchecker.git
headercheck https://example.com/
```

| Option | Rôle | Défaut |
|---|---|---|
| `-f`, `--format` | `text`, `json` ou `sarif` | `text` |
| `-o`, `--output` | Écrire le rapport dans un fichier | sortie standard |
| `--fail-on` | Seuil d'échec : `info`, `low`, `medium`, `high` ou `never` | `high` |
| `--origin` | Origine non fiable envoyée pour tester CORS | `https://headercheck.invalid` |
| `--sarif-artifact` | Fichier du dépôt auquel rattacher les résultats SARIF | l'URL analysée |
| `--timeout` | Délai maximal par requête, en secondes | `10` |

Codes de sortie : `0` pas de constat au-dessus du seuil, `1` au moins un constat au-dessus du
seuil, `2` une cible injoignable ou une erreur d'utilisation.

### Dans GitHub Actions

```yaml
- run: pip install git+https://github.com/omarsaidiA/headerchecker.git@<commit-sha>
- run: headercheck "$TARGET_URL" -f sarif -o headercheck.sarif --sarif-artifact openapi.yml
- uses: github/codeql-action/upload-sarif@<commit-sha>
  if: always()
  with:
    sarif_file: headercheck.sarif
    category: headercheck
```

## Développement

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"   # sous Windows : .venv\Scripts\pip
ruff check . && ruff format --check .   # lint (dont les règles de sécurité Bandit) et formatage
mypy                                    # typage strict
pytest                                  # tests et couverture d'au moins 90 %
```

Les tests de la ligne de commande lancent un vrai serveur HTTP local, dont chaque test choisit les
en-têtes de réponse.

## Licence

[MIT](LICENSE)
