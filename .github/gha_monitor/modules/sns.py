import boto3


class SNS_Client:
    params = {'topic_arn': None}

    def __init__(self):
        self.client = boto3.client('sns')

    def publish(self, message: None):
        """ Make the boto call """
        response = self.client.publish(TopicArn=self.params['topic_arn'], Message=message)
        return response
