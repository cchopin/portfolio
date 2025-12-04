# Investigation d'une campagne ransomware avec OpenCTI : quand une IP russe vous mène à un cartel cybercriminel

## Ou comment j'ai découvert que mes chèvres comprenaient mieux les réseaux criminels que moi

Il est 23h47. Je suis en train de nourrir mes chèvres (oui, encore) et je scroll distraitement sur Twitter/X pendant que Ragnar essaye de voler la bouffe des autres.

Un tweet d'un chercheur en sécurité : "New DragonForce campaign targeting transportation sector. IP 185.158.113.114 actively distributing malware."

Et là, je me dis : tiens, c'est l'occasion de tester OpenCTI. Parce que oui, j'utilise OpenCTI comme hobby. Pour tracker les menaces. Pour comprendre comment fonctionnent les groupes APT. Juste parce que c'est fascinant.

Avant OpenCTI, j'aurais passé 3 heures à googler l'IP, checker VirusTotal, scroller sur Reddit pour voir qui parle de DragonForce, et probablement finir sur un forum obscur en russe que Google Translate traduirait de manière... créative.

Ragnar, ma chèvre alpha, m'a regardé avec ce regard qui dit : "Tu vas encore passer la nuit sur ton ordi au lieu de réparer la clôture que j'ai défoncée cet après-midi, c'est ça ?"

Oui, Ragnar. Exactement.

Mais cette fois, avec OpenCTI, l'investigation complète a pris 15 minutes au lieu de 3 heures. Pour comprendre qui est DragonForce, comment ils opèrent, avec qui ils bossent, et pourquoi cette IP est intéressante.

Laissez-moi vous montrer comment on track une campagne APT depuis son canapé ou depuis un pré.

---

## Le contexte : DragonForce et Scattered Spider (ou : quand les méchants forment des cartels)

Mais d'abord, un peu de contexte. Parce qu'on ne va pas investiguer n'importe qui. On va parler du **DragonForce Cartel** et de leur collaboration avec **Scattered Spider**.

Si vous ne connaissez pas ces noms, imaginez :
- Un groupe de ransomware-as-a-service qui loue ses outils aux plus offrants
- Des alliances avec les groupes les plus connus : Scattered Spider (les gars qui ont pwn MGM Resorts en 2023), LAPSUS$ (ceux qui ont leak les sources de Microsoft et Samsung), et ShinyHunters (les collectionneurs de bases de données)
- Du code dérivé de Conti (oui, THE Conti, le ransomware le plus prolifique de 2021-2022)
- Des attaques BYOVD (Bring Your Own Vulnerable Driver) pour bypass les antivirus
- Plus de 200 victimes exposées sur leur leak site

En gros : le Avengers du cybercrime. Mais version méchants. Et russes. Avec probablement moins d'effets spéciaux et plus de tracksuit Adidas.

---

## L'investigation : de l'IP au cartel en 15 minutes

### Étape 1 : Le rapport d'AlienVault qui change tout

Je me connecte à mon instance OpenCTI (que j'héberge sur un VPS pour le fun). Et là, première bonne nouvelle : mon connecteur AlienVault OTX a automatiquement importé un rapport tout frais pendant que je dormais.

**"The DragonForce Cartel: Scattered Spider at the gate"**

Publication : 5 novembre 2025, 10:36 AM. Il y a littéralement quelques heures. La classe.

![Rapport DragonForce dans OpenCTI](/articles/assets/opencti-dragonforce-01.png)

Le rapport me dit tout de suite :
- **Type** : Threat Report
- **Auteur** : AlienVault (merci les gars)
- **99 entités liées** : Indicateurs, fichiers, techniques MITRE ATT&CK, secteurs ciblés
- **Labels** : affiliate program, byovd, cartel, coin, dragonforce, global, memmap, ramsonware, scattered spider, social engineering

En gros : OpenCTI me dit "Tely, ce que tu regardes, c'est pas juste une IP random trouvée sur Twitter. C'est un groupe structuré qui fait du ransomware-as-a-service avec des potes très connus. Et tu as toutes les infos ici."

Mes chèvres forment aussi des cartels pour voler la nourriture des autres. Je comprends le principe. Sauf que là, c'est documenté avec des graphes et des références MITRE au lieu de bêlements.

---

### Étape 2 : Le Knowledge Graph (ou : la visualisation qui impressionne ton N+1)

Je clique sur l'onglet **Knowledge** et là... boom.

![Knowledge Graph DragonForce](/articles/assets/opencti-dragonforce-02.png)

Un graphe avec des dizaines de nœuds connectés :
- **Le rapport central** (en rouge/orange au milieu)
- **Des dizaines d'indicateurs** (IPs, domaines, hashes de fichiers) en bleu clair
- **Des techniques MITRE ATT&CK** en jaune/orange
- **Des secteurs ciblés** en vert
- **Des malwares** en rose

Tout est relié. Tout fait sens. C'est beau. C'est organisé. C'est exactement le contraire de l'enclos de mes chèvres.

Ce graphe me montre en un coup d'œil :
- L'infrastructure du groupe (serveurs, IPs, domaines)
- Les outils utilisés (malwares, techniques)
- Les cibles (secteurs, géographies)

Ragnar m'a appris que la structure d'un réseau criminel ressemble à la hiérarchie d'un troupeau : il y a un leader (elle), des lieutenants (les chèvres qui la suivent partout), et des idiots utiles (les autres).

DragonForce, c'est pareil. Mais avec plus de Bitcoin et moins de foin.

---

### Étape 3 : Les détails du groupe (ou : qui sont ces gens ?)

Je retourne sur l'onglet **Overview** pour lire la description complète.

![Description complète DragonForce](/articles/assets/opencti-dragonforce-03.png)

Voici ce qu'OpenCTI me dit :

> **DragonForce**, un groupe de ransomware-as-a-service actif depuis 2023, s'est rebrandé en cartel et a formé des alliances avec des groupes comme **Scattered Spider**, **LAPSUS$**, et **ShinyHunters**.
>
> Le groupe utilise du **code dérivé de Conti** et emploie des **attaques BYOVD** (Bring Your Own Vulnerable Driver) pour terminer des processus.
>
> DragonForce a étendu son programme d'affiliation, permettant à des partenaires de créer des payloads whitelabel et des variantes.
>
> Le groupe a exposé **plus de 200 victimes** sur son leak site, ciblant différents secteurs.
>
> Le partenariat de DragonForce avec Scattered Spider, connu pour ses techniques d'ingénierie sociale sophistiquées, a conduit à des **brèches de haut profil**.
>
> Les échantillons de ransomware du groupe montrent un **chevauchement significatif** avec les fichiers sources leakés de Conti et utilisent le **chiffrement ChaCha20**.

En gros : ce sont des pros. Pas des script kiddies qui testent Metasploit dans leur garage.

Et la partie qui fait peur : "sophisticated social engineering techniques". Traduction : ils vont pas juste scanner vos ports. Ils vont appeler votre help desk en se faisant passer pour le CEO et demander un reset de mot de passe.

C'est exactement ce que fait Ragnar quand elle veut entrer dans la réserve de nourriture : elle bêle de manière pathétique devant la porte jusqu'à ce que quelqu'un cède. Social engineering niveau expert.

---

### Étape 4 : Les entités liées (ou : l'inventaire du crime)

Je clique sur l'onglet **Entities** pour voir ce qu'OpenCTI a importé.

![Liste des entités](/articles/assets/opencti-dragonforce-04.png)

**99 entités**, dont :
- **1 indicateur** : l'IP qui m'intéresse
- **2 secteurs** : Transportation, Technology
- **Des dizaines de techniques MITRE ATT&CK** :
  - T1566.003 (Spearphishing via Service)
  - T1566.002 (Spearphishing Link)
  - T1566.001 (Spearphishing Attachment)
  - T1110.003 (Password Spraying)
  - T1110.001 (Password Guessing)
  - T1078.004 (Cloud Accounts)
  - Et plein d'autres...

Chaque technique est **documentée**, **référencée dans MITRE ATT&CK**, et **liée au rapport**.

Avant OpenCTI, j'aurais dû chercher manuellement chaque technique sur le site MITRE. Là, tout est déjà importé, structuré, et prêt à être exploité.

C'est comme si quelqu'un avait déjà fait l'inventaire de ma réserve de foin au lieu de me laisser compter botte par botte pendant que mes chèvres essayent de voler le reste.

---

### Étape 5 : Les Observables (ou : les IoCs qui comptent)

Je vais dans l'onglet **Observables** pour voir les indicateurs de compromission.

![Liste des observables](/articles/assets/opencti-dragonforce-05.png)

Et là, jackpot :
- **Des dizaines de hashes de fichiers** (tous taggés "affiliate program", "byovd", "cartel")
- **Une adresse IP** : `185.158.113.114`

Tous ces observables sont :
- **Taggés** avec les bonnes catégories
- **Datés** (créés le 9 novembre 2025)
- **Sourcés** depuis AlienVault
- **Liés au rapport principal**

Et devine quoi ? L'IP `185.158.113.114`, c'est exactement celle que mon SOC vient de me signaler.

Coïncidence ? Je ne crois pas.

---

### Étape 6 : Investigation de l'IP (ou : destination Moscou)

Je clique sur l'IP pour voir les détails. Parce que oui, c'est exactement l'IP du tweet que j'avais vu.

![Détails de l'IP 185.158.113.114](/articles/assets/opencti-dragonforce-06.png)

OpenCTI me dit :
- **Value** : `185.158.113.114`
- **Type** : IPv4-Addr
- **Score** : 50/100 (niveau de confiance moyen)
- **Marking** : TLP:CLEAR (peut être partagé publiquement)
- **Labels** : affiliate program, byovd, cartel, coin, dragonforce, memmap, ramsonware, scattered spider, social engineering

Et surtout, les **relations** :
- **BASED ON** → Indicateur `185.158.113.114` (créé par AlienVault)
- **LOCATED AT** → **Moscow** (ville)
- **LOCATED AT** → **Russian Federation** (pays)
- **BELONGS TO** → **IP SERVER LLC** (le propriétaire de l'AS)

En 30 secondes, je sais :
- Où est hébergée cette IP (Moscou, Russie)
- À qui elle appartient (IP SERVER LLC)
- Qu'elle est liée à DragonForce
- Qu'elle est référencée dans un rapport d'AlienVault

Avant OpenCTI ? J'aurais :
1. Fait un whois sur l'IP
2. Cherché l'AS sur bgp.he.net
3. Googler "185.158.113.114" pour voir si quelqu'un en parle
4. Checker VirusTotal
5. Scroller sur Twitter avec `"185.158.113.114" malware`
6. Probablement finir sur un forum russe avec Google Translate qui me dit que "le serveur fait des choses suspicieuses avec des paquets" (merci Google)

Là ? **30 secondes**. OpenCTI a fait le boulot pendant que je nourrissais mes chèvres.

Mes chèvres ont un système similaire : quand l'une d'elles trouve quelque chose d'intéressant (genre un trou dans la clôture), elle prévient tout le troupeau en 10 secondes. Efficacité collective.

---

### Étape 7 : Le Knowledge Graph de l'IP (ou : tout est lié)

Je clique sur l'onglet **Knowledge** de l'IP pour voir ses relations.

![Knowledge de l'IP](/articles/assets/opencti-dragonforce-07.png)

Le graphe me montre :
- **BELONGS TO** → Autonomous System (IP SERVER LLC)
- **LOCATED AT** → Moscow
- **LOCATED AT** → Russian Federation
- **BASED ON** → Indicateur (créé par AlienVault)

Tout est propre. Tout est structuré. Tout est **exploitable**.

Si demain une autre IP du même AS apparaît dans mes logs, je saurai immédiatement qu'elle est potentiellement liée à DragonForce.

C'est le principe du **threat intelligence contextuel** : une IP toute seule ne veut rien dire. Une IP **liée à un groupe connu, hébergée dans un AS suspect, référencée dans un rapport récent** ? Ça, ça a du sens.

---

## Ce que j'ai appris (et ce que mes chèvres m'ont enseigné)

### Leçon 1 : La centralisation sauve du temps (et ta santé mentale)

Sans OpenCTI, j'aurais éparpillé mes recherches sur 15 sites différents. Avec OpenCTI, tout est au même endroit. C'est comme avoir une bibliothèque personnelle du cybercrime, sauf qu'elle se met à jour toute seule.

Ragnar a compris ce principe en centralisant l'accès à la mangeoire. Elle contrôle le point d'entrée. Elle sait qui mange quoi. Elle optimise le flow.

OpenCTI, c'est pareil. Mais pour les IoCs. Et sans les bêlements agressifs.

### Leçon 2 : Les relations comptent plus que les données brutes

Une IP seule ? Bof. Une IP **liée à un groupe APT, à des techniques MITRE, à des secteurs ciblés, à une géolocalisation** ? Là, on parle.

Mes chèvres fonctionnent en réseau. Ragnar ne domine pas juste parce qu'elle est grande. Elle domine parce qu'elle a des **relations** avec les autres chèvres, parce qu'elle connaît les **faiblesses** de chacune, et parce qu'elle sait **coordonner** les attaques sur la mangeoire.

DragonForce, c'est pareil. Et OpenCTI me permet de voir ce réseau.

### Leçon 3 : L'automatisation, c'est la clé

Mon connecteur AlienVault OTX a importé ce rapport **automatiquement**. Je dormais. Mes chèvres dormaient (enfin, Ragnar planifiait probablement son prochain coup). Et OpenCTI bossait.

C'est comme si mes chèvres se nourrissaient toutes seules sans détruire la clôture. Un rêve inaccessible. Mais au moins, mon threat intel fonctionne comme ça. Et ça, c'est beau.

### Leçon 4 : La visualisation aide à comprendre

Le Knowledge Graph est magnifique. Mais surtout, il est **utile**. En un coup d'œil, je vois les relations, les connexions, la structure.

Quand j'observe mes chèvres, je vois aussi un graphe : qui suit qui, qui domine qui, qui vole la bouffe de qui. C'est la même logique. Juste avec moins de bêlements et plus de JSON.

---

## La conclusion (ou : pourquoi vous avez besoin d'OpenCTI même si c'est juste pour le fun)

Cette investigation a pris **15 minutes**. D'un tweet random à une compréhension complète d'un cartel cybercriminel. Avec :
- Le contexte complet du groupe
- Les techniques utilisées
- Les IoCs associés
- La géolocalisation
- Les secteurs ciblés
- Les références externes

Avant OpenCTI ? **3 heures minimum**. Avec 47 onglets ouverts, une migraine, des notes éparpillées dans 5 fichiers texte, et probablement des infos incomplètes.

**Ce que j'ai maintenant :**
- Une compréhension complète de la menace
- Une vue d'ensemble de comment DragonForce opère
- Des IoCs à monitorer (même si c'est juste par curiosité)
- Une connaissance des TTPs modernes du ransomware
- De quoi briller en soirée quand quelqu'un parle de cybersécurité (bon, ok, ça n'arrive jamais)

**Ce que mes chèvres m'ont appris sur le threat intelligence :**
- La centralisation, c'est la puissance (Ragnar et la mangeoire)
- Les réseaux criminels fonctionnent comme les troupeaux (hiérarchie + coordination)
- L'automatisation sauve du temps (même si mes chèvres n'ont pas encore compris ce concept)
- La visualisation aide à prendre des décisions (observer les comportements)

---

## Les vraies prochaines étapes (si vous voulez monter votre propre OpenCTI)

1. **Installez OpenCTI** : Suivez mon guide d'installation (lien en bas)
2. **Configurez les connecteurs gratuits** : AlienVault OTX, MITRE ATT&CK, URLhaus
3. **Explorez** : Cliquez partout, suivez les relations, comprenez la structure
4. **Trackez ce qui vous intéresse** : APT chinois ? Ransomware ? Malware bancaire ? À vous de choisir
5. **Apprenez** : Chaque rapport est une leçon sur comment opèrent les attaquants

---

## Ressources

- **Rapport original AlienVault OTX** : [The DragonForce Cartel: Scattered Spider at the gate](https://otx.alienvault.com/)
- **OpenCTI** : https://www.opencti.io/
- **MITRE ATT&CK** : https://attack.mitre.org/
- **Mon guide d'installation OpenCTI** : [Lien vers votre article OpenCTI]

---

## La réflexion finale

Avant OpenCTI, je faisais du threat intelligence comme mes chèvres font du gardiennage : de manière chaotique, sans coordination, et avec beaucoup de bruit pour pas grand-chose.

Maintenant, quand je vois passer une IP ou un hash suspect sur Twitter, je sais :
- Qui c'est
- D'où ça vient
- Ce qu'ils veulent
- Comment ils opèrent
- À quel groupe ils appartiennent

En **15 minutes**. Depuis mon canapé. Avec Ragnar qui me regarde bizarrement parce que je souris devant mon écran.

**Pourquoi faire ça si c'est juste un hobby ?**

Parce que comprendre comment fonctionnent les attaquants, c'est fascinant. Parce que tracker des campagnes APT, c'est comme résoudre des puzzles géants. Parce que voir les connexions entre groupes, malwares, et infrastructures, c'est addictif.

Et surtout : parce que dans un monde où tout le monde est une cible potentielle, comprendre les menaces, c'est pas juste utile pour un boulot en cybersécurité. C'est utile pour **soi-même**.

OpenCTI, c'est mon Netflix de la threat intelligence. Sauf que c'est gratuit, open-source, et ça m'apprend des trucs utiles.

(Et mes chèvres approuvent, parce que je passe moins de temps à googler "APT28 latest campaign" et plus de temps à réparer leurs conneries.)

---

*PS : Ragnar a encore défoncé la clôture pendant que je finissais cet article. Elle a appliqué une technique d'ingénierie sociale sur la chèvre la plus faible pour qu'elle pousse de son côté pendant qu'elle tirait du sien. Scattered Spider serait fier.*

*PPS : DragonForce, si vous lisez ça : mes chèvres sont mieux organisées que vous. Et elles ont un meilleur nom. "DragonForce" ça sonne comme un groupe de metal des années 2000. Ragnar, c'est classe. Inspirez-vous.*

*PPPS : Sérieusement, si vous recevez une alerte avec cette IP (185.158.113.114), ne perdez pas de temps. Isolez la machine, capturez les logs, et commencez l'investigation. Et utilisez OpenCTI. S'il vous plaît.*
