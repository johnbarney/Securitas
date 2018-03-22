import boto3
import re
import datetime
import os


# Get today's date
TODAY = datetime.datetime.utcnow().date()

# AWS Administrator's group
AWS_ADMIN = os.environ['AWS_ADMIN']

# Boto3 Clients
IAM_CLIENT = boto3.client('iam')
IAM_RESOURCE = boto3.resource('iam')
SES_CLIENT = boto3.client('ses')

# Regex that verifies a valid email address
EMAIL_REGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

# Creates a list of users with valid emails as usernames
USERS = []

if not re.match(EMAIL_REGEX, AWS_ADMIN):
    raise ValueError('AWS Admin address is not a valid email!')

for u in IAM_CLIENT.list_users()['Users']:
    if re.match(EMAIL_REGEX, u['UserName']):
        USERS.append(u)
    else:
        print(f"User {u['UserName']}. Skipping...")


# Checks for API Key compliance
def keyrotation(event, context):
    for u in USERS:
        # Get all key pairs for a user
        key_pairs = IAM_CLIENT.list_access_keys(UserName=u['UserName'])
        for key_pair in key_pairs['AccessKeyMetadata']:
            # Only audit key pairs that are Active
            if key_pair['Status'] == 'Active':
                Id = key_pair['AccessKeyId']
                # 60 day warning
                if (key_pair['CreateDate'].date() - TODAY) == -60:
                    __compose_email(recipient=u['UserName'],
                                    subject="AWS Key expire in 30 days!",
                                    body=f"Your AWS Key {Id} will expire and "
                                    "will be deleted in 30 days. You can "
                                    "create a new key pair at any time via "
                                    "the console at any time. Please email "
                                    f"{AWS_ADMIN} with any questions.")
                # 5 day warning
                elif (key_pair['CreateDate'].date() - TODAY) == -85:
                    __compose_email(recipient=u['UserName'],
                                    subject="AWS Key expire in 5 days!",
                                    body=f"Your AWS Key {Id} will expire and "
                                    "will be deleted in 5 days. You can "
                                    "create a new key pair at any time via "
                                    "the console at any time. Please email "
                                    f"{AWS_ADMIN} with any questions.")
                # one day warning
                elif (key_pair['CreateDate'].date() - TODAY) == -89:
                    __compose_email(recipient=u['UserName'],
                                    subject="AWS Key expire tomorrow!",
                                    body=f"Your AWS Key {Id} will expire and "
                                    "will be deleted tomorrow. You can "
                                    "create a new key pair at any time via "
                                    "the console at any time. Please email "
                                    f"{AWS_ADMIN} with any questions.")
                # Delete key
                elif (key_pair['CreateDate'].date() - TODAY) < -90:
                    IAM_RESOURCE.AccessKey(
                        u['UserName'],
                        key_pair['AccessKeyId']).delete
                    __compose_email(recipient=u['UserName'],
                                    subject="AWS Key expired!",
                                    body=f"Your AWS Key {Id} was over 90 days "
                                    "old and has been deleted. You can create "
                                    "a new key pair at any time via the "
                                    "console at any time. Please email "
                                    f"{AWS_ADMIN} with any questions.")
    return {"message": "Finished key pair audit successfully."}


# Checks for MFA Compliance
def mfacheck(event, context):
    for u in USERS:
        device_list = IAM_CLIENT.list_mfa_devices(UserName=u['UserName'])
        if len(device_list['MFADevices']) == 0:
            __compose_email(recipient=u['UserName'],
                            subject="No MFA Device found!",
                            body="Your AWS account has no MFA device "
                            "associated. Please create one as soon as possible"
                            f"! Please email {AWS_ADMIN} with any questions.")
    return {"message": "Finished MFA audit successfully."}


# Pre-built email call
def __compose_email(recipient, subject, body):
    return SES_CLIENT.send_email(
        Source=AWS_ADMIN,
        Destination={
            'ToAddresses': [
                recipient
            ],
            'BccAddresses': [
                AWS_ADMIN
            ]
        },
        Message={
            'Subject': {
                'Charset': 'UTF-8',
                'Data': subject
            },
            'Body': {
                'Text': {
                    'Charset': 'UTF-8',
                    'Data': body
                },
                'Html': {
                    'Charset': 'UTF-8',
                    'Data': body
                }
            }
        },
        ReplyToAddresses=[
            AWS_ADMIN
        ],
        ReturnPath=AWS_ADMIN
    )
