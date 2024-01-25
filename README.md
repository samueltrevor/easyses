# EasySES: Simplify Your AWS SES Management

EasySES is a Python tool designed to streamline AWS Simple Email Service (SES) operations like domain setup, email sending, and sender verification.

## Table of Contents
1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Usage](#usage)
6. [License](#license)

## Features
- Set up new domains for SES.
- Send emails, both single and bulk.
- Verify single sender emails.
- Delete domains or sender emails.

## Prerequisites
- AWS Account with SES and IAM permissions.

## Installation
1. Clone the repository: `git clone https://github.com/samueltrevor/easyses`
2. Install required dependencies: `pip install -r requirements.txt`

## Configuration
1. Add the following variables to your `.env` file:
   - `AWS_ACCESS_KEY_ID`: Your AWS access key.
   - `AWS_SECRET_ACCESS_KEY`: Your AWS secret access key.
   - `SES_REGION_NAME`: Your AWS region.
   - `UNSUBSCRIBE_URL_KEY`: Your unsubscribe URL key. See instructions below.
   - `CONFIGURATION_SET`: Your AWS SES configuration set. This is optional.

2. Generate a Fernet key for encryption:
   ```python
   from cryptography.fernet import Fernet
   key = Fernet.generate_key()
   ```
   
    Add the key to your `.env` file as `UNSUBSCRIBE_URL_KEY`.

## Usage
### Set up a new domain

- **Add a new domain:**
   ```python
   dns_records = setup_new_domain(domain)
   ```
   Add the DNS records to your domain provider.


- **Check domain setup status:**
   ```python
   verify_dns_records(domain)
   ```

### Send emails

- **Bulk send:**

    ```python
    send_emails(
      subject,
      html_content,
      from_name,
      from_email,
      email_id,
      recipients, # A list of emails
      reply_to, # optional
      org_name, # your clients organisation name, it would be used in the unsubscribe footer
      bg_color  # optional, it sets the background color of the unsubscribe footer
   )
    ```

- **Single send:**

   There isn't a function for single send, Use your server's built-in SMTP client.
 

   **Example:**
   ```python
   send_mail(
       subject,
       body,
       from_email,
       [to_email],
       html_message=body,
       fail_silently=False,
   )
   ```
   Or use boto3 https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ses/client/send_email.html

### Delete a domain
```python
delete_domain(domain)
```

### Verify a sender email
_**Note:** sending emails without verifying the domain is not recommended._
```python
verify_sender_email(email)
```
This sends a verification email. For customization, upload an HTML template named `verification_email` to SES.


### Check single email status
```python
verify_sender_email(email)
```

### Delete a single sender
```python
delete_sender_email(email)
```

### Unsubscribe footer
Creates an encrypted unsubscribe link.
- **To decrypt the link:**
   ```python
   decrypt_link(encrypted_token)
   ```


   
   