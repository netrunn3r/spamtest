FROM alpine:3.12

EXPOSE 587

ARG HOSTNAME=mail
ARG DOMAIN=custom_msa.com

ADD main.cf /tmp

RUN apk update && apk --no-cache add \
    postfix cyrus-sasl cyrus-sasl-plain openssl ca-certificates \
    rsyslog \
    && cat /tmp/main.cf >> /etc/postfix/main.cf \
    && sed -i 's/^#submission/submission/' /etc/postfix/master.cf \
    && sed -i 's@^#  -o syslog_name=postfix/submission@  -o syslog_name=postfix/submission@' /etc/postfix/master.cf \
    && sed -i 's/^#  -o smtpd_tls_security_level=encrypt/  -o smtpd_tls_security_level=encrypt/' /etc/postfix/master.cf \
    && sed -i 's/^#  -o smtpd_sasl_auth_enable=yes/  -o smtpd_sasl_auth_enable=yes/' /etc/postfix/master.cf \
    && sed -i 's/^#  -o smtpd_tls_auth_only=yes/  -o smtpd_tls_auth_only=yes/' /etc/postfix/master.cf \
    && openssl genrsa -out mailing.key 2048 \
    && openssl req -new -key mailing.key -out mailing.csr -nodes -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    && openssl x509 -req -days 3650 -in mailing.csr -signkey mailing.key -out mailing.crt \
    && openssl req -new -x509 -extensions v3_ca -keyout cakey.pem -out cacert.pem -days 3650 -nodes -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" \
    && chmod 600 mailing.key \
    && chmod 600 cakey.pem \
    && chown postfix: mailing.key \
    && chown postfix: cakey.pem \
    && mv mailing.key /etc/ssl/private/ \
    && mv mailing.crt /etc/ssl/certs/ \
    && mv cakey.pem /etc/ssl/private/ \
    && mv cacert.pem /etc/ssl/certs/ \
    && sed -i 's/^module(load="imklog")/#module(load="imklog")/' /etc/rsyslog.conf \
    && sed -i 's/^kern.*/#kern.*/' /etc/rsyslog.conf \
    && sed -i 's/^*.emerg/#*.emerg/' /etc/rsyslog.conf \
    && sed -i 's/^#myhostname = host.domain.tld/myhostname = $HOSTNAME.$DOMAIN/' /etc/postfix/main.cf \
    && sed -i 's/^#mydomain = domain.tld/mydomain = $DOMAIN/' /etc/postfix/main.cf \
    && newaliases

ADD smtpd.conf /etc/sasl2/smtpd.conf
ADD entrypoint.sh /

RUN ln -sf /dev/stdout /var/log/mail.log

ENTRYPOINT [ "/entrypoint.sh" ]