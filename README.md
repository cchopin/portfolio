# Portfolio Cybersécurité - Clémence Chopin

Portfolio professionnel présentant mes compétences et projets en cybersécurité offensive et défensive, Database Administration et développement Nim.

## Design

- Design moderne et cyberpunk avec effet Matrix
- Thème sombre optimisé pour les yeux
- Couleurs accent cyan (#00f0ff)
- Entièrement responsive (desktop, tablet, mobile)
- Animations fluides et interactives

## Structure du projet

```
portfolio/
├── index.html              # Page d'accueil
├── projets.html           # Page des projets
├── competences.html       # Page des compétences
├── css/
│   └── style.css          # Styles CSS
├── js/
│   ├── matrix.js          # Effet Matrix background
│   └── main.js            # Fonctionnalités interactives
├── assets/                # Images et ressources
└── README.md             # Ce fichier
```

## Personnalisation

- **Nom** : Clémence Chopin
- **Titre** : Database Administrator & Cybersecurity Enthusiast
- **Email** : telynor@gmail.com
- **LinkedIn** : [clemence-chopin](https://www.linkedin.com/in/clemence-chopin/)
- **Expertise** : Database Administration, Nim Programming, Red/Blue Team, Drone, Chèvres
- **Certifications** :
  - M2I: Tests d'Intrusion (Pentesting) - Juin 2025
  - TryHackMe: Jr Penetration Tester - Mai 2025
  - TryHackMe: Cyber Security 101 - Avril 2025
  - TryHackMe: Web Fundamentals - Avril 2025
  - TryHackMe: Pre Security - Janvier 2025
  - CATT: Télépilote de Drone (DGAC) - Août 2022
  - CCAD: Certificat de Capacité Animaux (DRAAF) - Janvier 2017

## Fonctionnalités

### Page d'accueil
- Présentation professionnelle avec avatar
- Badges de compétences clés (Database Admin, Nim Lover, Red Team, Blue Team)
- Statistiques visuelles (projets, modules, langages)
- Grille d'expertise (6 domaines : DBA, Nim, Red Team, Blue Team, Drone, Chèvres)
- Section formation avec progression Jedha (5/16 modules)
- Section certifications (7 certifications dont M2I, TryHackMe, CATT, CCAD)
- Liens sociaux et contact

### Page projets
- Filtres interactifs par catégorie
  - Tous
  - Offensive Security
  - Defensive Security
  - DevSecOps
  - Éducation
- Cards détaillées pour chaque projet
- Tags technologiques
- Liens GitHub
- Descriptions et listes de fonctionnalités

### Page compétences
- Organisation par domaines
  - Offensive Security (Pentest, Web Security, Malware Dev, Hardware Hacking)
  - Defensive Security (SIEM, Threat Intelligence, Email Security, Incident Response)
  - Development (Python, Bash, Nim, SQL, Web, PowerShell)
  - DevSecOps (Docker, Ansible, Cloud, Web Servers)
  - Operating Systems (Linux, Windows)
  - Méthodologies (MITRE ATT&CK, OWASP, NIST, ISO 27001)
- Barres de progression animées
- Grille d'outils et technologies

### Interactivité JavaScript
- Navigation smooth scroll
- Filtrage de projets en temps réel
- Animations fade-in au scroll
- Barres de progression animées
- Compteurs animés pour les stats
- Easter egg (Konami Code)
- Effet Matrix en background

## Technologies utilisées

- **HTML5** - Structure sémantique
- **CSS3** - Variables CSS, Grid, Flexbox, Animations
- **JavaScript (Vanilla)** - Interactivité sans framework
- **Font Awesome 6.4** - Icônes
- **Google Fonts (Inter)** - Typographie moderne

## Installation et déploiement

### Local

```bash
# Cloner le repository
git clone git@github.com:cchopin/portfolio.git
cd portfolio

# Ouvrir dans le navigateur
open index.html
# ou
python3 -m http.server 8000
# puis aller sur http://localhost:8000
```

### Déploiement GitHub Pages

1. Aller dans les Settings du repository
2. Section "Pages"
3. Source: Deploy from a branch
4. Branch: `main` / `root`
5. Save

Le site sera accessible à : `https://tely.info`

### Déploiement Netlify

```bash
# Via Netlify CLI
npm install -g netlify-cli
netlify deploy --prod
```

Ou via l'interface Netlify :
1. Connecter le repository GitHub
2. Build settings : aucun build requis (site statique)
3. Publish directory : `/`
4. Deploy

## Personnalisation du design

### Couleurs

Modifier les variables CSS dans `css/style.css` :

```css
:root {
    --background: #0f0f11;
    --accent: #00f0ff;
    --surface: #1a1a1f;
    /* ... */
}
```

### Contenu

- **Projets** : Modifier `projets.html` pour ajouter/modifier des projets
- **Compétences** : Modifier `competences.html` pour les compétences
- **Informations personnelles** : Modifier `index.html`

### Effet Matrix

Personnaliser dans `js/matrix.js` :

```javascript
const chars = '01'.split('');  // Caractères affichés
const fontSize = 14;           // Taille de la police
```

## Projets présentés

1. **Nginx Attack Parser** - Analyseur de logs avec AbuseIPDB
2. **NimRAT Educational** - Framework éducatif de malware en Nim
3. **Formation Jedha** - Cybersécurité Full Stack (5/16 modules)
4. **Flipper Zero Evil Portal** - Portail captif WiFi ESP32
5. **Gestion SQL Ansible** - Automatisation PostgreSQL/MSSQL
6. **Nim Educational** - Parcours d'apprentissage Nim
7. **100 Red Team Projects** - Collection de projets offensifs
8. **Port Scanner Bash** - Scanner de ports natif
9. **CVE Arsenal Lab** - Laboratoire d'exploitation CVEs

## Sécurité

- Aucune donnée sensible dans le code
- Pas de tracking ou analytics par défaut
- Liens externes s'ouvrent dans un nouvel onglet
- Code minimaliste et auditable

## License

Ce portfolio est un projet personnel. Le code peut être utilisé comme template avec attribution.

## Contact

- **GitHub**: [github.com/cchopin](https://github.com/cchopin)
- **LinkedIn**: [linkedin.com/in/clemence-chopin](https://www.linkedin.com/in/clemence-chopin/)
- **Email**: telynor@gmail.com

---

**Note**: Ce portfolio est en constante évolution. Les projets et compétences sont régulièrement mis à jour au fil de ma progression dans la formation Jedha et mes projets personnels.

## TODO

- [ ] Ajouter section blog/articles techniques
- [ ] Ajouter mode clair/sombre toggle
- [ ] Ajouter section certifications
- [ ] Optimiser les images
- [ ] Ajouter meta tags SEO
- [ ] Ajouter Open Graph tags pour partage social
- [ ] Créer favicon personnalisé
- [ ] Ajouter section timeline de carrière

---

*Built with ❤️ and code by Clémence Chopin*
*Last updated: December 2025*
