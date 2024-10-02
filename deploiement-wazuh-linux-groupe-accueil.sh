#!/bin/bash

# Définition des variables
lien="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.2-1_amd64.deb"
SERVER="master.francecyberdefense.fr"
MASTER="master.francecyberdefense.fr"
SERVS="$SERVER"
CLIENT="GroupeAccueil"
GROUPES_DEFAUT="Linux,Serveur"

# Ajout du CLIENT à WAZUH_AGENT_GROUP
WAZUH_AGENT_GROUP="$GROUPES_DEFAUT,$CLIENT"

# Téléchargement du paquet Wazuh Agent et installation
wget $lien && sudo WAZUH_MANAGER="$SERVS" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" dpkg -i ./wazuh-agent_4.8.2-1_amd64.deb

# Pause de 5 secondes
sleep 5

# Rechargement du démon systemctl
systemctl daemon-reload

# Activation et démarrage du service wazuh-agent
systemctl enable wazuh-agent
systemctl start wazuh-agent
