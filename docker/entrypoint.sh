#!/bin/sh

domain="custom_msa.com"
user=$(openssl rand -base64 24 | tr -d /=+ | head -c 12)
pass=$(openssl rand -base64 40 | tr -d /=+ | head -c 20)
user="AtkUfa8KQbXI"  # for debuging, hardcoded
pass="YTINJBcgwdtSlMcYqU6N"

echo ${pass} | saslpasswd2 -p -c -u ${domain} ${user}
chown postfix: /etc/sasl2/sasldb2

echo "User: ${user}@${domain}"
echo "Pass: ${pass}"

#postfix -v start-fg
postfix start
rsyslogd -n
