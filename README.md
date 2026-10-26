# Veille quotidienne des vulnérabilités

Envoie chaque jour sur **Discord** et **Telegram** une synthèse des nouvelles vulnérabilités :

- **CISA KEV** : vulnérabilités activement exploitées ajoutées au catalogue
- **NVD** : nouvelles CVE publiées sur les dernières 24 h, filtrées par score CVSS (par défaut ≥ 7.0)

## 1. Créer les accès

**Discord** : Paramètres du salon > Intégrations > Webhooks > Nouveau webhook > copier l'URL.

**Telegram** :
1. Parler à `@BotFather`, commande `/newbot`, récupérer le token.
2. Envoyer un message à votre bot, puis ouvrir `https://api.telegram.org/bot<TOKEN>/getUpdates` et lire `chat.id`.

**NVD (optionnel)** : une clé API gratuite évite les limites de débit (https://nvd.nist.gov/developers/request-an-api-key).

## 2. Tester en local

```bash
cp .env.example .env        # remplir les valeurs
set -a; source .env; set +a
python vuln_digest.py --dry-run   # affiche sans envoyer
python vuln_digest.py             # envoie réellement
```

Aucune dépendance : uniquement la bibliothèque standard Python 3.9+.

## 3. Automatiser (GitHub Actions)

1. Poussez ce dossier dans un dépôt GitHub (privé de préférence).
2. Settings > Secrets and variables > Actions : ajouter `DISCORD_WEBHOOK_URL`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (et `NVD_API_KEY` si vous en avez une).
3. Le workflow `.github/workflows/vuln-digest.yml` s'exécute tous les jours à 06:00 UTC (08:00 en heure d'été française). Modifiez le `cron` pour changer l'heure. Vous pouvez aussi le lancer à la main depuis l'onglet Actions.

Alternative sans GitHub : une tâche cron sur un serveur, par exemple `0 8 * * * cd /chemin && set -a && . ./.env && python3 vuln_digest.py`.

## Réglages

| Variable | Défaut | Rôle |
|---|---|---|
| `MIN_CVSS` | 7.0 | Score minimum pour inclure une CVE |
| `LOOKBACK_HOURS` | 24 | Fenêtre de recherche |
| `MAX_NVD_ITEMS` | 25 | Nombre max de CVE détaillées |
