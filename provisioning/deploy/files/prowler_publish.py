import json
import time
import boto3
from botocore.exceptions import ClientError

# SnsWrapper source: https://github.com/awsdocs/aws-doc-sdk-examples/blob/main/python/example_code/sns/sns_basics.py
class SnsWrapper:
    """Encapsulates Amazon SNS topic and subscription functions."""
    def __init__(self, sns_resource):
        """
        :param sns_resource: A Boto3 Amazon SNS resource.
        """
        self.sns_resource = sns_resource

    @staticmethod
    def publish_multi_message(
            topic, subject, default_message, sms_message, email_message):
        """
        Publishes a multi-format message to a topic. A multi-format message takes
        different forms based on the protocol of the subscriber. For example,
        an SMS subscriber might receive a short, text-only version of the message
        while an email subscriber could receive an HTML version of the message.

        :param topic: The topic to publish to.
        :param subject: The subject of the message.
        :param default_message: The default version of the message. This version is
                                sent to subscribers that have protocols that are not
                                otherwise specified in the structured message.
        :param sms_message: The version of the message sent to SMS subscribers.
        :param email_message: The version of the message sent to email subscribers.
        :return: The ID of the message.
        """
        try:
            message = {
                'default': default_message,
                'sms': sms_message,
                'email': email_message
            }
            response = topic.publish(
                Message=json.dumps(message), Subject=subject, MessageStructure='json')
            message_id = response['MessageId']
            print("Published multi-format message to topic %s.", topic.arn)
        except ClientError:
            print("Couldn't publish message to topic %s.", topic.arn)
            raise
        else:
            return message_id


    def list_topics(self):
        """
        Lists topics for the current account.

        :return: An iterator that yields the topics.
        """
        try:
            topics_iter = self.sns_resource.topics.all()
            print("Got topics.")
        except ClientError:
            print("Couldn't get topics.")
            raise
        else:
            return topics_iter
        
    
    def create_topic(self, name):
        """
        Creates a notification topic.

        :param name: The name of the topic to create.
        :return: The newly created topic.
        """
        try:
            topic = self.sns_resource.create_topic(Name=name)
            print("Created topic %s with ARN %s.", name, topic.arn)
        except ClientError:
            print("Couldn't create topic %s.", name)
            raise
        else:
            return topic

def find_topic(topic_name):
    print('-'*50)
    to_return = ''
    for t in all_topics:
        print(str(t) + " | " + str(type(t)))
        if topic_name in str(t):
            to_return = t
    print('-'*50)
    return to_return

# Initialize sns wrapper
sns_wrapper = SnsWrapper(boto3.resource('sns', region_name='us-east-1'))
topic_name = 'prowler-updates-deployment'

all_topics = sns_wrapper.list_topics()
topic = ''

# Find the correct topic
topic = find_topic(topic_name)

# If the topic doesn't exist, then create it
if len(str(topic)) == 0:
    print("topic doesn't exist, creating...")
    sns_wrapper.create_topic('prowler-updates-deployment')
    # re-find the correct topic
    all_topics = sns_wrapper.list_topics()
    topic = find_topic(topic_name)

# Run through daily prowler output CSV
important_entries = list()
total_entries = 0
with open('output/daily_prowler.csv') as f:
    for line in f:
        total_entries += 1
        parsed_line = line.split(';')
        if 'critical' == parsed_line[10].lower():
            important_entries.append(parsed_line)
        if 'high' == parsed_line[10].lower():
            important_entries.append(parsed_line)

# Start writing output to message_content
message_content = ''
if len(important_entries) > 0:
    message_content = (message_content + 'Assessment date: ' + important_entries[0][0] 
            + '\nRisks found: ' + str(total_entries) 
            + '\nRisks listed (critical & high severity only): ' + str(len(important_entries)) + '\n')

# Write every "important entry" to message_content nicely formatted
for entry in important_entries:
    message_content = (message_content 
            + '\n' + '-'*(50 - len(entry[10])) + '[ Severity: ' + entry[10].upper() + ' ]' + '-'*(50 - len(entry[10]))
            + '\nRESOURCE ID: ' + entry[36] + ' (' + entry[8] + ')'
            + '\nDESCRIPTION: ' + entry[14]
            + '\nRISK: ' + entry[15]
            + '\nRECOMMENDATION: ' + entry[17] + ' | Read more: ' + entry[18]
            + '\n\nUNIQUE_ID: ' + entry[1] 
            + '\nCHECK_ID: ' + entry[3]
            + '\nCHECK_TITLE: ' + entry[4]
            + '\nRESOURCE_TYPE: ' + entry[11]
            + '\nRESOURCE ARN: ' + entry[37])

# publish the email
sns_wrapper.publish_multi_message(
            topic, 'Daily AWS Security Audit',
            message_content,
            message_content,
            message_content)