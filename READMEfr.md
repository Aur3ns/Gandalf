# Gandalf — Pare-feu IPv4 expérimental pour Linux

Gandalf est un **laboratoire de filtrage de paquets IPv4** écrit en Python. Cette nouvelle version remplace l'ancien serveur d'administration incomplet par un moteur de règles testable hors ligne et un mode Linux NFQUEUE **activé uniquement sur demande**.

> **Attention :** il ne s'agit pas d'un pare-feu de production. Ne testez pas l'interception réseau sur un poste distant en SSH. Utilisez une machine virtuelle jetable et gardez un accès console. Le programme **n'ajoute et ne supprime aucune règle iptables automatiquement**.

## Fonctionnalités

- Bloquer des adresses IPv4 sources et des réseaux CIDR.
- Bloquer des ports de destination TCP/UDP.
- Limiter les requêtes ICMP echo grâce à une fenêtre glissante.
- Bloquer éventuellement les fragments IPv4 : utile contre certains contournements, mais peut interrompre un trafic légitime.
- Surveiller en lecture seule les changements d'association IP/MAC par ARP (signal d'enquête, pas preuve d'une attaque).
- Simuler les décisions à partir d'un fichier JSONL sans réseau, privilège root ni dépendance externe.

## Démarrage rapide — sans modifier le réseau

Python 3.10 ou supérieur :

```bash
python3 gandalf.py --check-config
python3 -m unittest discover -s tests -v
```

Exemple de simulation :

```bash
printf '%s\n' '{"src":"192.168.43.181","protocol":"tcp","dport":443}' > /tmp/gandalf-test.jsonl
python3 gandalf.py --simulate /tmp/gandalf-test.jsonl
```

La configuration `firewallrules.json` est un **exemple comprenant de véritables interdictions** (notamment les ports 80 et 81, et le réseau `172.0.0.0/8`) : adaptez-la avant toute exécution réelle. Les préfixes réseau s'écrivent au format CIDR (`192.168.2.0/24`) et les booléens JSON sans guillemets (`true`/`false`).

## Filtrage réseau réel (VM Linux seulement)

Le mode `--live` nécessite les bibliothèques NFQUEUE et les privilèges root. Il écoute une file ; il **ne raccorde pas lui-même la file au pare-feu du système**.

Installez les prérequis et consultez la [documentation principale (anglais)](README.md#live-filtering-on-debian--ubuntu-disposable-vm-only) pour les commandes d'installation, les exemples de règles iptables avec `--queue-bypass`, et surtout la procédure de retrait **exacte** de la règle d'interception.

**Limites :** IPv4 seulement, aucun suivi d'état des connexions, pas d'inspection applicative, performances Python non qualifiées. `--queue-bypass` laisse passer les paquets lorsque le listener est absent ; il ne faut pas le considérer comme une protection haute disponibilité.

## Tests et sécurité

La CI compile le code, valide la configuration et lance les tests hors ligne sur plusieurs versions de Python. Ces tests **ne valent pas validation du noyau Linux, des performances réseau ni d'une protection contre des attaques réelles**.

Pour tous les détails techniques, la compatibilité, le déploiement et le dépannage, voir le [README principal](README.md).

Licence : MIT ([LICENSE](LICENSE)).