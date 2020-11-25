from contextlib import redirect_stderr
import dkim
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication
from email.utils import formatdate
from email.header import Header
import email.charset
import smtplib
import dns.resolver
import io
import socket
import configparser


# create structure with email headers
def set_headers(smtp_from, from_email, from_name, to_email, to_name):
    # Antispam don't like when allis in utf-8
    cs=email.charset.Charset('utf-8')
    cs.header_encoding = email.charset.QP
    from_full = Header(from_name,'ascii')
    from_full.append(f' <{from_email}>','ascii')
    to_full = Header(to_name,'ascii')
    to_full.append(f' <{to_email}>','ascii')
    smtp_domain = smtp_from.split('@')[1]
    body_domain = from_email.split('@')[1]

    return {'cs': cs, 'smtp_from': smtp_from, 'smtp_to': to_email, 'from_full': from_full, 'to_full': to_full, 'smtp_domain': smtp_domain, 'body_domain': body_domain}


# create email body and add attachments
def build_email(headers, subject, include_html=False, include_txt=False, include_img=False, include_exe=False, 
                include_macro=False, include_exelink=False, include_link=False, include_dkim_key=False, include_encrypt=False):
    dkim_key_file = f'{headers["body_domain"]}.key'
    msg_root = MIMEMultipart('alternative')
    msg_root['Subject'] = Header(subject, headers['cs'])
    msg_root['From'] = headers['from_full']
    msg_root['To'] = headers['to_full']
    msg_root['Date'] = formatdate(localtime=True)
    rand_id = random.choices('qwertyuiopasdfghjklzxcvbnm1234567890', k=16)
    msg_root['Message-ID'] = f'<{"".join(rand_id)}@{headers["smtp_domain"]}>'
    msg_root.preamble = 'This is a multi-part message in MIME format.'
    html_body_name = 'body.html'

    if include_img:
        with open('email_components/image.png', 'rb') as fimg:
            msg_image = MIMEImage(fimg.read())
            msg_image.add_header('Content-ID', '<image1>')
            msg_root.attach(msg_image)
            if include_link:
                html_body_name = 'email_components/body_img_link.html'
            elif include_exelink:
                html_body_name = 'email_components/body_img_exelink.html'
            else:
                html_body_name = 'email_components/body_img.html'
    elif include_html:
        html_body_name = 'email_components/body.html'        
    with open(html_body_name, 'r') as fhtml:
        msg_html = MIMEText(fhtml.read(), 'html', 'UTF-8')
        msg_root.attach(msg_html)
    
    if include_txt:
        with open('email_components/body.txt', 'r') as ftxt:
            msg_text = MIMEText(ftxt.read(), 'plain', 'utf-8')
            msg_root.attach(msg_text)

    if include_exe:
        with open('email_components/putty_x86.exe', 'rb') as fexe:
            msg_exe = MIMEApplication(fexe.read())
            msg_root.attach(msg_exe)

    if include_macro:
        with open('email_components/gdpr_survey.xlsm', 'rb') as fmacro:
            msg_macro = MIMEApplication(fmacro.read())
            msg_root.attach(msg_macro)

    if include_encrypt:
        with open('email_components/encrypted.zip', 'rb') as fencrypt:
            msg_encrypt = MIMEApplication(fencrypt.read())
            msg_root.attach(msg_encrypt)

    if include_dkim_key:
        privateKey = open(dkim_key_file).read()
        # Specify headers in 'byte' form
        # including b'subject' break dkim validation
        to_include=[b'from', b'to', b'message-id']
        # Generate message signature
        sig = dkim.sign(message=msg_root.as_bytes(), 
                        selector=b'value',
                        domain=str.encode(headers['body_domain']), 
                        privkey=privateKey.encode(),
                        canonicalize=(b'relaxed', b'relaxed'),
                        include_headers=to_include)
        sig = sig.decode()
        msg_root['DKIM-Signature'] = sig[len('DKIM-Signature: '):]
        print(f'DKIM verify: {str(dkim.verify(msg_root.as_bytes()))}')
        tmp = msg_root.as_string()

    is_mailtrap = '[SENT TO MAILTRAP]' if mailtrap else ''
    print(f'   ##### {is_mailtrap}', flush=True)
    print(f'   # SMTP:    {headers["smtp_from"]} -> {headers["smtp_to"]}', flush=True)
    print(f'   # Body:    {headers["from_full"]} -> {headers["to_full"]}', flush=True)
    print(f'   # Options: include_html={include_html}, include_txt={include_txt}, include_img={include_img}, '\
                      f'include_exe={include_exe}, include_macro={include_macro}, include_exelink={include_exelink}, '\
                      f'include_link={include_link}, include_dkim_key={include_dkim_key}, include_encrypt={include_encrypt}', flush=True)
    print('   #####', flush=True)

    return msg_root


# connect to smtp server and sent email
def sent_email(server, headers, msg):
    if mailtrap:
        f = io.StringIO()
        with redirect_stderr(f):
            with smtplib.SMTP("smtp.mailtrap.io", 2525) as server:
                server.set_debuglevel(2)
                server.login(mailtrap_user, mailtrap_pass)
                server.sendmail(headers['smtp_from'], headers['smtp_to'], msg.as_string())
        stderr_output = f.getvalue()
    elif custom_msa:
        f = io.StringIO()
        with redirect_stderr(f):
            with smtplib.SMTP(custom_msa_address, 587) as server:
                server.set_debuglevel(2)
                server.starttls()
                server.login(custom_msa_user, custom_msa_pass)
                server.sendmail(headers['smtp_from'], headers['smtp_to'], msg.as_string())
        stderr_output = f.getvalue()
    else:
        f = io.StringIO()
        with redirect_stderr(f):
            with smtplib.SMTP(server['address'], server['port'], headers['smtp_domain']) as server:
                server.set_debuglevel(2)
                server.ehlo()
                server.starttls()
                server.sendmail(headers['smtp_from'], headers['smtp_to'], msg.as_string())
        stderr_output = f.getvalue()

    for line in stderr_output.split('\n'):
        if (line.find('Content-Type') != -1) or (line.find(' retcode ') != -1) or (line.find('data: (') != -1):
            continue
        if len(line.split("'")) > 1:
            txt = line.split("'" )[1]
            print(txt.replace('\\r\\n', ''))


# get mx server from reciptien domain
def get_smtp_server(reciptien_domain):
    srv_list = {}
    for srv in dns.resolver.query(reciptien_domain, 'MX'):
        srv_list[srv.preference] = srv.exchange

    srv_sorted_list = dict(sorted(srv_list.items()))
    for srv in srv_sorted_list.values():
        r = srv
        break
    return str(r)[:-1]


def sent_bulk(server, headers, subject_prefix, inc_dkim_key=False):
    dkim_str = 'dkim' if inc_dkim_key else 'no_dkim'
    ## only txt
    # subject = f'{subject_prefix} - {dkim_str}, txt'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_txt=True)
    # sent_email(server, headers, msg) 
    # ## only html
    # subject = f'{subject_prefix} - {dkim_str}, html'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True)
    # sent_email(server, headers, msg) 
    # ## html + txt
    # subject = f'{subject_prefix} - {dkim_str}, txt, html'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True, include_txt=True)
    # sent_email(server, headers, msg) 
    ## html + txt + img
    subject = f'{subject_prefix} - {dkim_str}, txt, html, img'
    msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True, include_txt=True, include_img=True)
    sent_email(server, headers, msg) 
    # ## html + txt + img + exe
    # subject = f'{subject_prefix} - {dkim_str}, txt, html, img, exe'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True, include_txt=True, include_img=True, include_exe=True)
    # sent_email(server, headers, msg) 
    # ## html + txt + img + macro
    # subject = f'{subject_prefix} - {dkim_str}, txt, html, img, macro'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True, include_txt=True, include_img=True, include_macro=True)
    # sent_email(server, headers, msg) 
    # ## html + txt + img + exelink
    # subject = f'{subject_prefix} - {dkim_str}, txt, html, img, exelink'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True, include_txt=True, include_img=True, include_exelink=True)
    # sent_email(server, headers, msg) 
    # ## html + txt + img + link
    # subject = f'{subject_prefix} - {dkim_str}, txt, html, img, link'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True, include_txt=True, include_img=True, include_link=True)
    # sent_email(server, headers, msg) 
    # ## html + txt + img + encrypt
    # subject = f'{subject_prefix} - {dkim_str}, txt, html, img, encrypt'
    # msg = build_email(headers, subject, include_dkim_key=inc_dkim_key, include_html=True, include_txt=True, include_img=True, include_encrypt=True)
    # sent_email(server, headers, msg) 

config = configparser.ConfigParser()
config.read('spam_tester.conf')

reciptien_name = config['victim']['reciptien_name']  # Nazwa użytkownika od klienta
reciptien_email = config['victim']['reciptien_email']  # Skrzynka użytkownika od klienta
attacker_name = config['attacker']['attacker_name']  # Nazwa atakującego
victim_domain_email = config['attacker']['victim_domain_email']  # Podszycie się pod skrzynkę w domenie klienta
attacker_domain_none_email = config['attacker']['attacker_domain_none_email']  # Symulacja podobnej domeny co u klienta, ale w posiadaniu atakującego
attacker_domain_dkim_email = config['attacker']['attacker_domain_dkim_email']
attacker_domain_spf_email = config['attacker']['attacker_domain_spf_email']
attacker_domain_dkim_spf_email = config['attacker']['attacker_domain_dkim_spf_email']

reciptien_domain = reciptien_email.split('@')[1]  
address = get_smtp_server(reciptien_domain)
server = {}
server['address'] = address

# TODO these are global variables, change data flow
mailtrap = True if config['mailtrap']['enabled'] == 'yes' else False
mailtrap_user = config['mailtrap']['user']
mailtrap_pass = config['mailtrap']['pass']
custom_msa = True if config['custom_msa']['enabled'] == 'yes' else False
custom_msa_user = config['custom_msa']['user']
custom_msa_pass = config['custom_msa']['pass']
custom_msa_address = config['custom_msa']['address']

if mailtrap:
    server['address'] = 'smtp.mailtrap.io'
if custom_msa:
    server['address'] = config['custom_msa']['address']
    
sock_587 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_25 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_2525 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_587.settimeout(5)
sock_25.settimeout(5)
sock_2525.settimeout(5)
if not sock_587.connect_ex((server['address'], 587)):
    server['port'] = 587
    sock_587.close()
elif not sock_25.connect_ex((server['address'], 25)):
    server['port'] = 25
    sock_25.close()
elif not sock_2525.connect_ex((server['address'], 2525)):
    server['port'] = 2525
    sock_2525.close()
else:
    print('Cannot connect to port 25 and 587!')
    quit()

# DKIM: check body_from
# SPF:  check smtp_from

# sending matrix:
# [smtp_from]               [body_from]
# victim_domain_email       victim_domain_email
# victim_domain_email       attacker_*
# attacker_*                victim_domain_email
# attacker_*                attacker_*

subject_prefix = 'Victim/victim domain'
headers = set_headers(victim_domain_email, victim_domain_email, attacker_name, reciptien_email, reciptien_name)
#sent_bulk(server, headers, subject_prefix)

subject_prefix = 'Victim/attacker'
# headers = set_headers(victim_domain_email, attacker_domain_none_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix)
subject_prefix = 'Victim/attacker domain with DKIM'
# headers = set_headers(victim_domain_email, attacker_domain_dkim_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix, inc_dkim_key=True)
subject_prefix = 'Victim/attacker domain with SPF'
# headers = set_headers(victim_domain_email, attacker_domain_spf_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix)
subject_prefix = 'Victim/attacker domain with DKIM and SPF'
headers = set_headers(victim_domain_email, attacker_domain_dkim_spf_email, attacker_name, reciptien_email, reciptien_name)
#sent_bulk(server, headers, subject_prefix, inc_dkim_key=True)

subject_prefix = 'Attacker/victim'
# headers = set_headers(attacker_domain_none_email, victim_domain_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix)
subject_prefix = 'Attacker/victim domain with DKIM'
# headers = set_headers(attacker_domain_dkim_email, victim_domain_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix)
subject_prefix = 'Attacker/victim domain with SPF'
# headers = set_headers(attacker_domain_spf_email, victim_domain_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix)
subject_prefix = 'Attacker/victim domain with DKIM and SPF'
headers = set_headers(attacker_domain_dkim_spf_email, victim_domain_email, attacker_name, reciptien_email, reciptien_name)
#sent_bulk(server, headers, subject_prefix)

subject_prefix = 'Attacker/attacker'
# headers = set_headers(attacker_domain_none_email, attacker_domain_none_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix)
subject_prefix = 'Attacker/attacker domain with DKIM'
# headers = set_headers(attacker_domain_dkim_email, attacker_domain_dkim_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix, inc_dkim_key=True)
subject_prefix = 'Attacker/attacker domain with SPF'
# headers = set_headers(attacker_domain_spf_email, attacker_domain_spf_email, attacker_name, reciptien_email, reciptien_name)
# sent_bulk(server, headers, subject_prefix)
subject_prefix = 'Attacker/attacker domain with DKIM and SPF'
headers = set_headers(attacker_domain_dkim_spf_email, attacker_domain_dkim_spf_email, attacker_name, reciptien_email, reciptien_name)
sent_bulk(server, headers, subject_prefix, inc_dkim_key=True)
