## What this does
aws-prowler-ec2-to-sns provisions an ec2 instance with:
- [prowler](https://github.com/prowler-cloud/prowler)
- systemd files to run prowler automatically (once every day on weekdays)
- a python script which will look through important prowler information and send it to ab AWS Simple Email Service (SNS) topic named prowler-updates-deployment (it will be created automatically if it doesn't already exist)
- install dependencies for everything

## Usage
1. Create an IAM role with the following permissions policies:
- `BaselineECRAdminAccess`
- `BaselineS3ReadWriteAccess`
- `BaselineSSMSessionsPolicy`
- `AmazonSNSFullAccess`
- `AmazonSSMFullAccess`
- `AmazonMQReadOnlyAccess`
- `AmazonSSMManagedInstanceCore`
- `AmazonSSMPatchAssociation`
- `AmazonSSMManagedEC2InstanceDefaultPolicy`

2. Create an Ubuntu AWS EC2 instance under the new IAM role

### Inside the ec2 instance: 
3. Install ansible `apt install ansible`
4. Clone this repository `git clone https://github.com/battleofthebots/aws-prowler-ec2-to-sns.git`
5. Run the ansible playbook `/usr/bin/ansible-playbook provisioning/playbook.yml`

At this point, `/etc/systemd/system/prowler.timer` is configured to execute `prowler.service` every weekday at 12:00pm UTC. 

This systemd service will run prowler then send the AWS SNS email to the `prowler-updates-deployment` topic. 

6. Inside the SNS topic settings for `prowler-updates-deployment`, add your desired e-mail addresses to a subscription. These addresses will recieve the daily prowler updates. 

## Installed packages (apt)
- python3.9-venv

## Installed packages (pip)
- prowler

## Author information
Daniel Wolosiuk