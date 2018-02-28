Securitas
=========

A basic set of Lambdas for AWS that covers User security. AWS Config can alert admins, but does not cover enforcement/encouragement. Built using the [Serverless Framework](https://serverless.com/)

### Assumptions:

This Lambda makes some assumptions about your setup.

* You are using IAM Users
* Your IAM UserNames are valid email addresses. (Others will be ignored completely)
* You want to go with the standard best practice of 90 day expiration on API key pairs
* You strongly want users to have MFA devices
* You have set up a distribution group for your AWS Administrators
* You have a verified the AWS Administrators distribution group with SES

### How to Install:

To install without cloning you can install from this repo.

```bash
npm install -g serverless

serverless install -u https://github.com/johnbarney/Securitas --awsadmin (AWS Administrators distribution group)
```

### What to Expect:

* Users will be notified DAILY if they do not have an MFA Device associated with their account.
* Users will be notified at 60, 85, and 89 days that their AWS key pair will expire.
* Key pairs over 90 days old and ACTIVE will be automatically deleted and users will be informed that the key as been deleted.

### Contributing

Standard fork/pull request contributions are welcome with the caveat that I may politely decline for any reason.
