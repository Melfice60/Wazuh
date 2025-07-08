#/bin/bash
#v3
#Déploiement d'un serveur et dashboard avec wazuh 4.10.1
#s'assurer que l'archive de certificats  et le dossier d'integrations se trouvent dans le meme dossier

INDEX_NAME='basan-indexer-1'
NODE_NAME='wazuh-basan-1'  # garder les ' et retirer les <>
DASHBOARD_NAME='dashboard-wazuh-basan'  # garder les ' et retirer les <>

echo -e "127.0.0.1 basan-indexer-1.local" >> /etc/hosts
echo -e "127.0.0.1 wazuh-basan-1.local" >> /etc/hosts
echo -e "dashboard-basan.local" >> /etc/hosts

#mise a jour des packages pour s'assurer pas de dysfonctionnement
apt-get install debconf adduser procps
apt-get install gnupg apt-transport-https
apt-get install debhelper tar curl libcap2-bin

#installation des clés GPG
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

# ajout des repos wazuh
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

#mise a jour des repos et deploiement wazuh
apt-get update


apt-get -y install wazuh-manager=4.10.1-1



#deploiement filebeat
apt-get -y install filebeat

#telechargement fichier config filebeat
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.10/tpl/wazuh/filebeat/filebeat.yml

#sed qui permettra de configurer filebeat correctement
sed -i 's/hosts: \["127.0.0.1:9200"\]/hosts: \["indexer.francecyberdefense.fr:9200"\]/' /etc/filebeat/filebeat.yml

#creation et introduction des identifiants dans le keystore filebeat
filebeat keystore create
echo admin | filebeat keystore add username --stdin --force
echo 0aWWrlAk41ftDPZYDAVfchE?2Z1P+11e | filebeat keystore add password --stdin --force

#recuperation du template d'alerte et installation du module filebeat pour wazuh
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.10.1/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module

sed -i 's|<host>https://0.0.0.0:9200</host>|<host>https://indexer.francecyberdefense.fr:9200</host>|' /var/ossec/etc/ossec.conf

#déploiement des certificats
mkdir /etc/filebeat/certs
tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chown -R root:root /etc/filebeat/certs

#Mise en place de la connexion indexer
/var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
/var/ossec/bin/wazuh-keystore -f indexer -k password -v 0aWWrlAk41ftDPZYDAVfchE?2Z1P+11e

#déploiement du paquet d'integration fourni
rm -r /var/ossec/integrations/*
mkdir /var/ossec/integrations
sudo cp -r integrations/* /var/ossec/integrations/
chmod 750 /var/ossec/integrations/*
chown root:wazuh /var/ossec/integrations/*

#demarrage du filebeat
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat


#activation et demarrage de la fonction wazuh
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

#controle de l'activité
filebeat test output

#activation du framework thehive
/var/ossec/framework/python/bin/pip3 install thehive4py==1.8.1

apt-get -y install wazuh-dashboard=4.10.1-1

#sed qui permettra de configurer opensearch correctement
sed -i 's/opensearch.hosts: https://localhost:9200/hosts: \["https://indexer.francecyberdefense.fr:9200"\]/' /etc/wazuh-dashboard/opensearch_dashboards.yml

#deploiement des identifiants adaptes
echo URw.qReBDTGBojnpW1YGZLeyaZV4q4VP | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password

#deploiement des certificats
mkdir /etc/wazuh-dashboard/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$DASHBOARD_NAME.pem ./$DASHBOARD_NAME-key.pem ./root-ca.pem
mv -n /etc/wazuh-dashboard/certs/$DASHBOARD_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv -n /etc/wazuh-dashboard/certs/$DASHBOARD_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs


systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

#Desac des possibilités d'update pour ne pas casser la conf

sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
apt update
