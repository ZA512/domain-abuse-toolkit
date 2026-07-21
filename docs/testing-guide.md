# Guide de test local

Ce premier test valide le parcours produit sans contacter de site suspect.

## Prérequis

- Windows 10 ou 11 ;
- WSL 2 avec Ubuntu ;
- Python 3.12 ou supérieur dans WSL ;
- accès Internet lors du premier lancement pour installer les dépendances Python.

Les dossiers de test sont conservés dans le répertoire privé WSL :

```text
~/.local/share/domain-abuse-toolkit/case-data
```

Ils ne sont pas écrits dans le dépôt Git public.

## Lancer l’application

Double-cliquer sur `START_TOOLKIT.cmd` à la racine du projet.

Le lanceur :

1. vérifie WSL et Python ;
2. prépare un environnement Python privé dans WSL ;
3. ouvre une fenêtre serveur visible ;
4. attend que l’application réponde ;
5. ouvre `http://127.0.0.1:8080/` dans le navigateur par défaut.

Le premier lancement peut durer une ou deux minutes. Les suivants sont plus rapides.

Pour arrêter, utiliser `Ctrl+C` dans la fenêtre intitulée **Domain Abuse Toolkit - Serveur**, fermer cette fenêtre ou double-cliquer sur `STOP_TOOLKIT.cmd`.

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
45 passed
SUCCES - tous les controles passent.
```

Le nombre de tests peut augmenter au fil du développement. Après avoir créé un dossier, enregistrer la qualification puis une soumission synthétique, arrêter et relancer l’application permet également de vérifier que le dossier, sa criticité confirmée, son état `waiting_external`, sa référence et son échéance de relance réapparaissent dans le suivi local.

## Limite de ce premier test

La collecte réseau, les captures, les envois, Microsoft Graph et l’IA restent désactivés. L’enregistrement d’une soumission est une confirmation humaine locale : l’outil ne soumet aucun formulaire et n’envoie aucun message. Ce test porte sur l’expérience de création de dossier, la préparation du workflow, l’intégrité du stockage local, les brouillons et le cadencement de la première relance.
