import json
import boto3
import jwt
import os
#import logging

COGNITO_REGION = os.environ['COGNITO_REGION']
COGNITO_USER_POOL_ID = os.environ['COGNITO_USER_POOL_ID']
COGNITO_APP_CLIENT_ID = os.environ['COGNITO_APP_CLIENT_ID']

cognito_client = boto3.client('cognito-idp', region_name=COGNITO_REGION)


#logger = logging.getLogger()
#logger.setLevel(logging.INFO)
#logger.info('Started!')


def lambda_handler(event, context):
    try:
        query_params = event.get('queryStringParameters')
        if query_params and 'token' in query_params:
            access_token = query_params['token']
            response = cognito_client.get_user(
                AccessToken=access_token
            )
            #logger.info("Cognito Response: %s", response)
            
            # Generate an IAM policy to allow access
            policy = generate_policy('user', 'Allow', event['methodArn'])

            # Return the policy as the auth response
            return {
                'principalId': 'user',
                'policyDocument': policy,
            }
        return {
            'statusCode': 401,
            'body': json.dumps({'message': 'Invalid token'})
        }
    except Exception as e: 
        #logger.error("Lambda function failed with error: %s", str(e))
        return {
            'statusCode': 500,
            'body': json.dumps({'message': 'Internal server error'})
        }

# Helper function to generate an IAM policy
def generate_policy(principal_id, effect, resource):
    policy_document = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }
        ]
    }

    return policy_document
