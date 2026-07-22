# Guide de test local

Ce premier test valide le parcours produit sans contacter de site suspect.

## Prérequis

- Windows 10 ou 11 avec Docker Desktop pour le lancement recommandé ;
- accès Internet lors du premier lancement pour télécharger l'image Python et installer les dépendances ;
- WSL 2 avec Ubuntu et Python 3.12 ou supérieur uniquement pour les lanceurs historiques et le mode de collecte passive actuel.

## Lancer l'application avec Docker (recommande)

1. démarrer Docker Desktop ;
2. arrêter toute copie utilisant déjà le port 8080 ;
3. double-cliquer sur `START_TOOLKIT_DOCKER.cmd` ;
4. ouvrir `http://127.0.0.1:8080/` si le navigateur ne s'ouvre pas ;
5. arrêter avec `STOP_TOOLKIT_DOCKER.cmd`.

Le premier démarrage construit l'image et peut prendre quelques minutes. Les dossiers sont conservés dans le volume Docker nommé `domain-abuse-toolkit-evidence`. L'arrêt ne supprime pas ce volume. Ce profil est entièrement local : la collecte réseau, les captures, l'IA, Microsoft Graph et les envois sont désactivés, et le réseau Docker interne n'offre aucune sortie Internet.

Les dossiers de test sont conservés dans le répertoire privé WSL :

```text
~/.local/share/domain-abuse-toolkit/case-data
```

Ils ne sont pas écrits dans le dépôt Git public.

## Lancer l'application avec WSL (transition)

Double-cliquer sur `START_TOOLKIT.cmd` à la racine du projet. Cette voie reste disponible pendant la migration vers Docker Compose.

Le lanceur :

1. vérifie WSL et Python ;
2. prépare un environnement Python privé dans WSL ;
3. ouvre une fenêtre serveur visible ;
4. attend que l’application réponde ;
5. ouvre `http://127.0.0.1:8080/` dans le navigateur par défaut.

Le premier lancement peut durer une ou deux minutes. Les suivants sont plus rapides.

Pour arrêter, utiliser `Ctrl+C` dans la fenêtre intitulée **Domain Abuse Toolkit - Serveur**, fermer cette fenêtre ou double-cliquer sur `STOP_TOOLKIT.cmd`.

## Activer volontairement la collecte technique

Le lancement standard et le profil Docker conservent tout accès réseau désactivé. Pour tester le collecteur actuel, utiliser temporairement le lanceur WSL dédié :

1. démarrer Docker Desktop ;
2. arrêter le serveur avec `STOP_TOOLKIT.cmd` ;
3. double-cliquer sur `START_TOOLKIT_NETWORK.cmd` ;
4. lire l’avertissement puis entrer `OUI` ;
5. patienter pendant la première construction de l’image Playwright ; les lancements suivants réutilisent cette image sans relancer Docker Build ;
6. ouvrir un dossier synthétique autorisé ;
7. cocher l’autorisation dans **Collection**, puis cliquer sur **Start passive evidence collection** ;
8. rafraîchir la fiche si le job est encore `queued` ou `running`.

### Tester le suivi UP/DOWN planifié

Ce test contacte périodiquement la cible. Il doit donc être effectué uniquement en mode
réseau et sur une cible autorisée :

1. ouvrir l'étape **Suivi** d'un dossier disposant déjà d'un relevé technique ;
2. vérifier que la dernière disponibilité affiche `UP`, `DOWN probable` ou `Inconnu`,
   avec l'heure du contrôle ;
3. choisir une fréquence dans **Contrôles UP/DOWN planifiés** ;
4. confirmer l'autorisation continue puis activer la surveillance ;
5. vérifier la date exacte du prochain contrôle sur le dossier et l'accueil.

Le planificateur ne fonctionne que tant que Domain Abuse Toolkit est ouvert. Sa
configuration est persistée : après un redémarrage, un contrôle en retard est repris.
Chaque passage planifié collecte uniquement DNS, HTTP et TLS. Il ne lance ni RDAP, ni
capture, ni JavaScript, ni formulaire, ni message. `UP` signifie seulement qu'une réponse
HTTP a été reçue ; `DOWN probable` doit être confirmé par un humain.

Si le Dockerfile ou le worker de capture a été modifié, un mainteneur peut forcer la reconstruction avec :

```powershell
PowerShell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-toolkit.ps1 -EnableNetworkCollection -EnableScreenshots -ForceCaptureImageBuild
```

La construction est retentée trois fois si Docker Desktop verrouille temporairement ses métadonnées.

Cette action interroge les enregistrements DNS `A`, `AAAA`, `CNAME`, `MX`, `NS` et `TXT`, effectue une navigation HTTP/TLS bornée, puis découvre le service RDAP officiel depuis le registre IANA. Le résultat RDAP fournit notamment le registrar, son contact d’abus lorsqu’il est publié, les statuts et les dates du domaine. Le HTML et jusqu’à huit feuilles `text/css` admissibles sont collectés avec les mêmes contrôles d’adresse, puis rendus hors ligne dans un conteneur jetable : réseau désactivé, JavaScript désactivé, système de fichiers en lecture seule, ressources bornées et aucun profil personnel. La capture est marquée comme dérivée du corps HTTP et des CSS utilisés. Aucun formulaire, cookie, script ou téléchargement n’est exécuté. Utiliser exclusivement une cible autorisée ; `example.com` convient pour un essai synthétique.

## Scénario de test conseillé

Utiliser uniquement les valeurs synthétiques suivantes :

| Champ | Valeur |
|---|---|
| URL suspecte | `https://login.example.net/account?source=test` |
| Marque | `Example Brand` |
| Site légitime | `https://www.example.com/` |
| Type | `Phishing / credentials` |
| Urgence | `Immediate` |

Vérifier ensuite :

- que le chemin `/account` est conservé ;
- que la criticité proposée est `critical` ;
- que quatre prochaines actions apparaissent ;
- que les brouillons anglais et français sont présents ;
- que les boutons de copie fonctionnent ;
- que **Open email client** ouvre un brouillon sans l’envoyer.
- que **Download evidence ZIP** télécharge une archive contenant le manifeste et le vérificateur.
- que les canaux officiels suggérés apparaissent avec leur date de vérification ;
- que les résumés français et anglais sont copiables ;
- qu’une adresse saisie dans **Email recipient** est ajoutée au brouillon ouvert dans le client mail.
- qu’une soumission réellement effectuée peut être confirmée dans **Record a completed submission** avec sa référence externe ;
- que le dossier passe à `waiting_external` et affiche automatiquement la prochaine échéance de relance.
- que l'accueil et l'étape **Suivi** affichent la prochaine action de procédure, sa date exacte et un indicateur lorsqu'elle est à faire ;
- en mode réseau volontaire, qu’un snapshot affiche les résultats DNS, HTTP, TLS, RDAP et SCREENSHOT, montre la capture statique avec les feuilles CSS externes admissibles, et ajoute le HTML, les CSS et la capture dérivée au ZIP de preuve ;
- qu’après une deuxième collecte, les changements normalisés apparaissent avant les détails bruts et que la prochaine date de contrôle est visible dans le dossier et sur l’accueil.

Après extraction complète du ZIP, ouvrir PowerShell dans le dossier du dossier exporté puis lancer :

```powershell
wsl.exe python3 verify_evidence.py .
```

Le résultat attendu commence par `VERIFIED:`. Toute modification, suppression ou injection de fichier doit faire échouer la vérification.

## Lancer les contrôles automatiques

Double-cliquer sur `RUN_TESTS.cmd`.

La fenêtre doit terminer par :

```text
All checks passed!
75 passed
SUCCES - tous les controles passent.
```

Le nombre de tests peut augmenter au fil du développement. Après avoir créé un dossier, enregistrer la qualification puis une soumission synthétique, arrêter et relancer l’application permet également de vérifier que le dossier, sa criticité confirmée, son état `waiting_external`, sa référence et son échéance de relance réapparaissent dans le suivi local.

## Limite de ce premier test

Les envois, Microsoft Graph et l’IA restent désactivés. La collecte DNS/HTTP/TLS/RDAP et le rendu statique peuvent être activés volontairement. Le rendu n’est pas une capture complète d’un site dynamique : seules les feuilles `text/css` admissibles sont collectées séparément puis injectées hors ligne ; scripts, images, polices, imports CSS et autres ressources restent bloqués. Les réponses RDAP brutes peuvent contenir des données personnelles publiées par le registre. L’enregistrement d’une soumission est une confirmation humaine locale : l’outil ne soumet aucun formulaire et n’envoie aucun message.
