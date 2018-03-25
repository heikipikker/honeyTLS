#!/bin/bash

sudo sh -c "echo 'deb http://download.opensuse.org/repositories/network:/bro/xUbuntu_16.04/ /' > /etc/apt/sources.list.d/bro.list"
apt-get -y --force-yes update
apt-get -y --force-yes upgrade

## nginx
apt-get -y install nginx
mkdir /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/C=GB/ST=London/L=London/O=Something/OU=IT Department/CN=STH"
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
IP=$(dig +short myip.opendns.com @resolver1.opendns.com)
echo "server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $IP;
    return 302 https://\$server_name\$request_uri;
}

server {

    # SSL configuration

    listen 11211 ssl http2 default_server;
    listen 161 ssl http2 default_server;
    listen 9100 ssl http2 default_server;
    listen 631 ssl http2 default_server;
    listen 515 ssl http2 default_server;
    listen 1080 ssl http2 default_server;
    listen 5060 ssl http2 default_server;
    listen 137 ssl http2 default_server;
    listen 53 ssl http2 default_server;
    listen 5432 ssl http2 default_server;
    listen 25 ssl http2 default_server;
    listen 21 ssl http2 default_server;
    listen 110 ssl http2 default_server;
    listen 143 ssl http2 default_server;
    listen 2222 ssl http2 default_server;
    listen 23 ssl http2 default_server;
    listen 445 ssl http2 default_server;
    listen 9200 ssl http2 default_server;
    listen 8000 ssl http2 default_server;
    listen 8081 ssl http2 default_server;
    listen 8888 ssl http2 default_server;
    listen 3389 ssl http2 default_server;
    listen 5000 ssl http2 default_server;
    listen 500 ssl http2 default_server;
    listen 1433 ssl http2 default_server;
    listen 3306 ssl http2 default_server;
    listen 1883 ssl http2 default_server;
    listen 8883 ssl http2 default_server;
    listen 5061 ssl http2 default_server;
    listen 27017 ssl http2 default_server;
    listen 27018 ssl http2 default_server;
    listen 27019 ssl http2 default_server;
    listen 995 ssl http2 default_server;   
    listen 994 ssl http2 default_server;
    listen 993 ssl http2 default_server;
    listen 992 ssl http2 default_server;
    listen 990 ssl http2 default_server;
    listen 989 ssl http2 default_server;
    listen 636 ssl http2 default_server;
    listen 563 ssl http2 default_server;
    listen 465 ssl http2 default_server;
    listen 614 ssl http2 default_server;
    listen 448 ssl http2 default_server;
    listen 261 ssl http2 default_server;
    listen 8080 ssl http2 default_server;
    listen 8443 ssl http2 default_server;
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name $IP;
    ssl_certificate /etc/nginx/ssl/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx.key;
}" > /etc/nginx/sites-available/default
# adding $server_port to the access log
echo 'user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 768;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;
    log_format mycombinedplus '\''$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $server_port'\'';
    access_log /var/log/nginx/access.log mycombinedplus;
    error_log /var/log/nginx/error.log;
    gzip on;
    gzip_disable "msie6";
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}' > /etc/nginx/nginx.conf
systemctl restart nginx

## bro
apt-get -y install \
	cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
apt-get -y --allow-unauthenticated install bro
export PATH=/opt/bro/bin:$PATH
echo "@load tuning/json-logs" >> /opt/bro/share/bro/site/local.bro
echo "redef LogAscii::json_timestamps = JSON::TS_ISO8601;" >> /opt/bro/share/bro/site/local.bro

# JA3
mkdir /opt/bro/share/bro/site/ja3
wget https://raw.githubusercontent.com/salesforce/ja3/master/bro/__load__.bro -O /opt/bro/share/bro/site/ja3/__load__.bro
wget https://raw.githubusercontent.com/salesforce/ja3/master/bro/intel_ja3.bro -O /opt/bro/share/bro/site/ja3/intel_ja3.bro
wget https://raw.githubusercontent.com/salesforce/ja3/master/bro/ja3.bro -O /opt/bro/share/bro/site/ja3/ja3.bro
echo "@load ./ja3" >> /opt/bro/share/bro/site/local.bro
# Uncomment lines to log all aspects of the SSL Client Hello Packet
sed -i '/string &optional/s/^#//g' /opt/bro/share/bro/site/ja3/ja3.bro
sed -i '/c$ssl$ja3/s/^#//g' /opt/bro/share/bro/site/ja3/ja3.bro

# Start Bro
broctl install
broctl start
broctl status


echo ""
echo "====================="
echo " Happy Honeypotting! "
echo "====================="
echo ""