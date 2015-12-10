#!/bin/bash
set -e

if [[ ! -d /data/etc ]]; then
    mkdir /data/etc
fi

if [[ ! -d /data/etc/apache2 ]]; then
    cp -r /etc/apache2 /data/etc
fi

rm -Rf /etc/apache2
ln -s /data/etc/apache2 /etc/apache2

mkdir /var/cache/apache2/mod_auth_cas
chown -R www-data /var/cache/apache2/mod_auth_cas

echo Using apache2 configuration in /data/etc/apache2
echo Please build and install mod_auth_cas and then run "service apache2 start"

cd /data && /bin/bash
