from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
import requests
import time
import json
from jinja2 import Template
from botocore.exceptions import ClientError
import boto3
from decouple import config


# Change to your companies branding.
# This would be at the start of the DNS records.
SELECTOR = 'mycompany'
SES_REGION_NAME = config('SES_REGION_NAME')  # e.g. 'eu-north-1'
CONFIGURATION_SET = config('CONFIGURATION_SET')  # optional
DOMAIN = config('DOMAIN')


def ses_client(client='ses'):
    return boto3.client(
        client,
        aws_access_key_id=config('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=config('AWS_SECRET_ACCESS_KEY'),
        region_name=SES_REGION_NAME
    )


ses = ses_client()
ses2 = ses_client('sesv2')

# Get the existing send rate per second.
ses_max_send_rate = int(ses.get_send_quota().get('MaxSendRate'))
THROTTLE = 0.5
send_rate = int(THROTTLE * ses_max_send_rate)


unsubscribe_cipher_suite = Fernet(config('UNSUBSCRIBE_URL_KEY'))

# Verification states to user-friendly terms.
VERIFICATION_STATUSES = {
    'success': 'success',
    'pending': 'pending',
    'failed': 'failed',
    'temporaryfailure': 'pending',
    'temporary_failure': 'pending',
    'notstarted': 'pending',
}


# Create DNS records.

def create_domain(domain):
    response = ses.verify_domain_identity(
        Domain=domain
    )
    return response


def extract_identity_record(domain, response):
    identity_record = {
        'type': 'TXT',
        'name': '_amazonses.' + domain,
        'value': response['VerificationToken']
    }
    return identity_record


def generate_ssl_certificate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_pem_lines = pem_public_key.decode('utf-8').replace("-----BEGIN PUBLIC KEY-----\n", "").replace(
        "-----END PUBLIC KEY-----\n", "").strip()
    public_key_pem_one_line = "".join(public_key_pem_lines.splitlines())

    private_key_pem_lines = pem_private_key.decode('utf-8').replace("-----BEGIN PRIVATE KEY-----\n", "").replace(
        "-----END PRIVATE KEY-----\n", "").strip()
    private_key_pem_one_line = "".join(private_key_pem_lines.splitlines())

    return {
        'public_key': public_key_pem_one_line,
        'private_key': private_key_pem_one_line
    }


def create_dkim_record(domain, private_key):
    response = ses2.put_email_identity_dkim_signing_attributes(
        EmailIdentity=domain,
        SigningAttributesOrigin='EXTERNAL',
        SigningAttributes={
            'DomainSigningSelector': SELECTOR,
            'DomainSigningPrivateKey': private_key
        }
    )
    return response


def extract_dkim_record(domain, public_key):
    dkim_record = {
        'type': 'TXT',
        'name': SELECTOR + '._domainkey.' + domain,
        'value': f"v=DKIM1; k=rsa; p={public_key}"
    }
    return dkim_record


def create_mail_from_records(domain):
    response = ses.set_identity_mail_from_domain(
        Identity=domain,
        MailFromDomain=SELECTOR + '.' + domain
    )
    return response


def extract_mail_from_records(domain):
    records = [
        {
            'type': 'MX',
            'name': SELECTOR + '.' + domain,
            'value': '10 feedback-smtp.' + SES_REGION_NAME + '.amazonses.com'
        },
        {
            'type': 'TXT',
            'name': SELECTOR + '.' + domain,
            'value': 'v=spf1 include:amazonses.com -all'
        }
    ]
    return records


def setup_new_domain(domain):
    records = {
        'identity': {},
        'dkim': {},
        'mail_from': []
    }

    response = create_domain(domain)
    records['identity'] = extract_identity_record(domain, response)

    ssl_keys = generate_ssl_certificate()
    create_dkim_record(domain, ssl_keys['private_key'])
    records['dkim'] = extract_dkim_record(domain, ssl_keys['public_key'])

    create_mail_from_records(domain)
    records['mail_from'] = extract_mail_from_records(domain)
    return records


# Check DNS records status.
def verify_identity_record(domain):
    response = ses.get_identity_verification_attributes(
        Identities=[
            domain,
        ]
    )
    status = {
        'identity': VERIFICATION_STATUSES.get(
            response['VerificationAttributes'][domain]['VerificationStatus'].lower(), 'failed')
    }
    return status


def verify_dkim_and_mail_from_records(domain):
    response = ses2.get_email_identity(
        EmailIdentity=domain
    )
    status = {
        'dkim': VERIFICATION_STATUSES.get(response['DkimAttributes']['Status'].lower(), 'failed'),
        'mail_from': VERIFICATION_STATUSES.get(response['MailFromAttributes']['MailFromDomainStatus'].lower(), 'failed')
    }
    return status


def verify_dns_records(domain):
    identity_status = verify_identity_record(domain)
    dkim_and_mail_from_status = verify_dkim_and_mail_from_records(domain)
    status = {**identity_status, **dkim_and_mail_from_status}
    return status


# Delete Domain.
def delete_domain(domain):
    response = ses.delete_identity(
        Identity=domain
    )
    return response


# Send Email.
def create_ses_template(template_name, subject, html_content, org_name, bg_color='inherit'):
    context = {
        'background_color': bg_color,
        'organization_name': org_name
    }

    with open('html/footer.html', 'r') as f:
        footer = f.read()

    footer = Template(footer).render(context)
    footer = footer.replace('\n', '')
    footer = footer.replace('UNSUBSCRIBE_URL', '{{unsubscribe_url}}')
    footer = footer.replace('REPORT_URL', '{{report_url}}')
    template_data = {
        'TemplateName': template_name,
        'SubjectPart': subject,
        'HtmlPart': html_content + footer,
    }
    try:
        response = ses.create_template(Template=template_data)
    except ClientError as e:
        if e.response['Error']['Code'] == 'AlreadyExists':
            response = ses.update_template(Template=template_data)
        else:
            raise e

    return response


def delete_ses_template(template_name):
    response = ses.delete_template(
        TemplateName=template_name
    )
    return response


def encrypt_link(email, additional_data: dict = None):
    data = json.dumps({'email': email, **additional_data})
    encrypted_token = unsubscribe_cipher_suite.encrypt(data.encode())
    return encrypted_token.decode()


def decrypt_link(encrypted_token):
    decrypted_token = unsubscribe_cipher_suite.decrypt(encrypted_token.encode())
    return decrypted_token.decode()


def send_bulk_emails(template_name, from_name, from_email, recipients, reply_to):
    reply_to = reply_to or from_email
    destinations = []
    for recipient in recipients:
        for email in recipient:
            encrypted_link = encrypt_link(email)
            unsubscribe_url = f'{DOMAIN}/unsubscribe/{encrypted_link}/'
            report_url = f'{DOMAIN}/report-email/{encrypted_link}/'
            destinations.append({
                'Destination': {
                    'ToAddresses': [email],
                },
                'ReplacementTemplateData': f'{{"unsubscribe_url":"{unsubscribe_url}",'
                                           f'"report_url":"{report_url}"}}',
                # AWS SES tags. optional.
                'ReplacementTags': [
                    {
                        'Name': 'email',
                        'Value': email
                    }
                ],
            })
    for batch in range(0, len(destinations), send_rate):
        batch_destinations = destinations[batch:batch + send_rate]
        ses.send_bulk_templated_email(
            Source=f"{from_name} <{from_email}>",
            Template=template_name,
            DefaultTemplateData='{}',
            ReplyToAddresses=[reply_to],
            Destinations=batch_destinations,
            ConfigurationSetName=CONFIGURATION_SET,
        )
        time.sleep(1)
    return True


def send_emails(subject, html_content, from_name, from_email, email_id, recipients: list, reply_to, org_name, bg_color):
    create_ses_template(email_id, subject, html_content, org_name, bg_color)
    send_bulk_emails(email_id, from_name, from_email, recipients, reply_to)
    delete_ses_template(email_id)
    return True


def create_sender_email(email):
    ses2.send_custom_verification_email(
        EmailAddress=email,
        TemplateName=f'verification_email'
    )
    return True


def verify_sender_email(email):
    response = ses2.get_email_identity(
        EmailIdentity=email
    )
    status = response['VerifiedForSendingStatus']
    return status


def delete_sender_email(email):
    ses2.delete_email_identity(
        EmailIdentity=email
    )
    return True

