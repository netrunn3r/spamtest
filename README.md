# spamtest
This tool is design to verify effectiveness of antispam solutions. It send lots of crafted emails, which are more or less compliant with email standards and contains more or less elements which can suggest that this is a spam.

## How it works
### Architecture
spamtest have two elements:
1. main script to send emails from operator host
2. postfix server in docker, which is configured as a MSA to 'proxy' emails from operator to target MTA server

Postfix is required because:
1. ISP of operator can block port 25, which sometimes is needed to send emails
2. operator has a better chance to change rDNS on VPS (where postfix can be deployed) than on his host / gateway

### Main script
Main script, spam_tester.py, has two phases of constructing emails
1. mangling `SMTP FROM` and `body From` headers
2. creating emails with different contantes

#### Mangling headers
Headers are mangling in this way:
(attacker is a synonym of operator)
| [smtp_from]         | [body_from]         |
|---------------------|---------------------|
| victim_domain_email | victim_domain_email |
| victim_domain_email | attacker_*          |
| attacker_*          | victim_domain_email |
| attacker_*          | attacker_*          |

Where attacker_* are:
1. operator domain without DKIM and SPF (e.g. none.spamtest.operator-domain.com)
2. operator domain with only DKIM (e.g. dkim.spamtest.operator-domain.com)
3. operator domian with only SPF (e.g. spf.spamtest.operator-domain.com)
4. operator domain with both DKIM and SPF (e.g. dkim-spf.spamtest.operator-domain.com)

Side note:
* DKIM check `body From:`
* SPF check `SMTP FROM`

#### Creating emails
spam_tester.py create:
1. simply, plain email where content is in text form
2. email with content in html
3. email with both text and html content
4. email with both text and html content, additionaly with big image
5. email with both text and html content, additionaly with big image and executable (windows exe file) as a attachment
6. email with both text and html content, additionaly with big image and MS Excel spreedsheet with macros as a attachemnt
7. email with both text and html content, additionaly with big image and link to executable (windows exe file)
8. email with both text and html content, additionaly with big image and link to some page
9. email with both text and html content, additionaly with big image and encrypted zip archive

## Deployment
### spam_tester.py
#### Installation
Just install dependencies from requirements file:
`pip install -r requirements.txt`

spam_tester.py is a Python 3 script, so you need that version of Python (tested on 3.7.7).

#### Generating DKIM keys
For each domain which will have DKIM records, i.e.:
1. dkim.spamtest.operator-domain.com
2. dkim-spf.spamtest.operator-domain.com

We need generate private and public keys:
1. `openssl genrsa -out dkim.spamtest.operator-domain.com.key 2048`
2. `openssl rsa -in dkim.spamtest.operator-domain.com.key -pubout -out dkim.spamtest.operator-domain.com.pub`
3. `openssl genrsa -out dkim-spf.spamtest.operator-domain.com.key 2048`
4. `openssl rsa -in dkim-spf.spamtest.operator-domain.com.key -pubout -out dkim-spf.spamtest.operator-domain.com.pub`

**spam_tester.py will be looking for filename exactly like `body From:` header with .key suffix.**

#### Config file
You can configure spam_tester.py in file spam_tester.conf, which looks like this:
```ini
[victim]
reciptien_name = John Smith
reciptien_email = john.smith@example.com

[attacker]
attacker_name = Uncle Fred
victim_domain_email = uncle.fred@example.com
attacker_domain_none_email = uncle.fred@none.ex4mple.com
attacker_domain_dkim_email = uncle.fred@dkim.ex4mple.com
attacker_domain_spf_email = uncle.fred@spf.ex4mple.com
attacker_domain_dkim_spf_email = uncle.fred@dkim-spf.ex4mple.com

[mailtrap]
enabled = yes
user = some_user
pass = some_pass

[custom_msa]
enabled = yes
address = 127.0.0.1
user = msa_user
pass = msa_pass
```

`[victim]` section is about target email, to which we will send our mails. `reciptien_email` is used as a value of `SMTP RCPT` and `body To:` headers, where `reciptien_name` in `body To:` header.

`[attacker]` section configure which addresses will be used as a `SMTP FROM` and `body From:` headers. In this example:
1. domain _example.com_ is domain which belong to target, operator cannot configure it
2. domain _ex4mple.com_ is domain which belong to operator, which he can configure and add new record. **In this README it is operator-domain.com**

`[mailtrap]` section enable or disable sending emails to mailtrap.io, where you can debug your emails. `user` and `pass` are credentials to authenticate in this service.

`[custom-msa]` section is our postfix-msa container, with parameters to connect and to enable it. If both mailtrap and custom_msa are enabled, then mailtrap will have higher priority and mails will be sent to that service. In out examples in this document, address of custom_msa is mail.spamtest.operator-domain.com

### Postfix
To simplify deployment, docker container has been prepared with preconfigured Postfix to act as a MSA. To build image below command can be performed:

`docker build --pull --rm -f "path\to\spamtest\docker\Dockerfile" -t postfix-msa:latest --build-arg HOSTNAME=mail --build-arg DOMAIN=spamtest.operator-domain.com spamtest "path\to\spamtest\docker"`

Then, container can be run:

`docker run --rm -it --name spamtest -p 587:587 --hostname mail --domainname spamtest.operator-domain.com`

Where:
* `--build-arg HOSTNAME=mail` and `--hostname mail` is hostname of docker container
* `--build-arg DOMAIN=spamtest.operator-domain.com` and `--domainname spamtest.operator-domain.com` is domain of docker container
Both will be in rDNS and it will be use in comunication with target MTA server as mail.spamtest.operator-domain.com

After run a container, it will display output from syslog - connections to postfix.

### DNS
You need to add this DNS records (assume, that operator-domain.com is your domain):
```bind
dkim-spf.spamtest                      60 IN MX     10 dkim-spf.spamtest.operator-domain.com.
dkim-spf.spamtest                      60 IN A      POSTFIX-MSA_EXTERNAL_IP
dkim-spf.spamtest                      60 IN TXT    "v=spf1 a mx ip4:POSTFIX-MSA_EXTERNAL_IP ~all"
dkim.spamtest                          60 IN MX     10 dkim.spamtest.operator-domain.com.
dkim.spamtest                          60 IN A      POSTFIX-MSA_EXTERNAL_IP
mail.spamtest                          60 IN A      POSTFIX-MSA_EXTERNAL_IP
none.spamtest                          60 IN MX     10 none.spamtest.operator-domain.com.
none.spamtest                          60 IN A      POSTFIX-MSA_EXTERNAL_IP
spf.spamtest                           60 IN MX     10 spf.spamtest.operator-domain.com.
spf.spamtest                           60 IN A      POSTFIX-MSA_EXTERNAL_IP
spf.spamtest                           60 IN TXT    "v=spf1 a mx ip4:POSTFIX-MSA_EXTERNAL_IP ~all"
value._domainkey.dkim-spf.spamtest     60 IN TXT    ( "v=DKIM1;h=sha256;k=rsa;p=PUBLIC KEY;" )
value._domainkey.dkim.spamtest         60 IN TXT    ( "v=DKIM1;h=sha256;k=rsa;p=PUBLIC KEY;" )
```
Where:
* POSTFIX-MSA_EXTERNAL_IP - external IP address of VPS on which docker witch postfix-msa container is running
* PUBLIC KEY - content of files dkim/dkim-spf.spamtest.operator-domain.com.pub, but **without** lines started with '---'. Also you need to concatenate all lines to one line, then this one line add to DNS record.

In VPS configuration (propably some web page from VPS provider) set this rDNS (Reverse DNS): `mail.spamtest.operator-domain.com`

## Run
Just execute spam_tester.py - simply, isn't it? :)
