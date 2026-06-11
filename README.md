# RustyTools — Diagnostic réseau

Outil de diagnostic pour administrateurs réseau, système et sécurité. Application
graphique native (egui), multiplateforme : **Windows, macOS, Linux**.

## Fonctionnalités (v1)

### 📡 Ping continu
- Ping simultané de plusieurs cibles (IP ou FQDN, une par ligne)
- Intervalle et timeout configurables
- Statistiques en direct : envoyés, reçus, perte (%), RTT dernier/min/moy/max, gigue
- Un fichier de log CSV horodaté par cible :
  `logs/ping_<date>_<cible>.csv` au format
  `horodatage;cible;ip;seq;statut;rtt_ms;gigue_ms`
  (statut : `OK`, `TIMEOUT` en cas de perte de paquet, ou `ERREUR: …`)

La gigue est calculée comme la variation entre deux RTT consécutifs ; le tableau
affiche la gigue moyenne de la session.

### 🛣 Traceroute
- Plusieurs cibles en parallèle, sortie en direct
- Option de résolution des noms des sauts
- Mode « répéter en continu » avec intervalle entre passes
- Un fichier de log horodaté par cible : `logs/traceroute_<date>_<cible>.log`
- S'appuie sur l'outil système : `tracert` (Windows), `traceroute` (macOS/Linux),
  avec repli sur `tracepath` sous Linux

### 🖧 Configuration réseau
- Nom d'hôte, domaine, serveurs DNS
- Interfaces : état (UP/DOWN), type, MAC, IPv4 + masque, IPv6, passerelle, DNS,
  interface par défaut
- Table de routage complète
- Sorties brutes des outils système (`ipconfig /all`, `ifconfig`, `ip addr`, …)
- Export du rapport complet en fichier texte

## Compilation

Prérequis : [Rust](https://rustup.rs) (édition 2021).

```bash
cargo build --release
```

Le binaire se trouve dans `target/release/rustytools` (`rustytools.exe` sous
Windows). Compiler sur (ou pour) chaque OS cible pour obtenir les trois
exécutables.

Dépendances système sous Linux (exemple Debian/Ubuntu) pour l'interface
graphique :

```bash
sudo apt install build-essential libgtk-3-dev libxcb-render0-dev \
  libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

## Privilèges ICMP

| OS | Comportement |
|----|--------------|
| Windows | Aucun privilège requis (API `IcmpSendEcho`) |
| macOS | Aucun privilège requis (socket ICMP datagramme) |
| Linux | Socket non privilégié si `net.ipv4.ping_group_range` l'autorise (cas général sur les distributions récentes) ; sinon repli automatique sur socket brut, qui nécessite root ou `setcap cap_net_raw+ep` |

Si aucun des deux modes n'est disponible, l'erreur est affichée dans l'interface
avec la marche à suivre.

## Logs

Tous les fichiers sont écrits dans le répertoire configurable dans l'interface
(`logs/` par défaut, créé automatiquement). Chaque ligne est horodatée à la
milliseconde.
