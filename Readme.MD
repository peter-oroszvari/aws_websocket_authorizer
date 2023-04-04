# Cognito Auth Lambda

This AWS Lambda function is a custom authorizer for API Gateway that authenticates users using Amazon Cognito User Pools. When a request is made to the API Gateway, this Lambda function will be invoked to verify the user's access token and generate an IAM policy based on the provided token.

## Requirements

- Python 3.9
- AWS Lambda
- Amazon API Gateway
- Amazon Cognito User Pool
- Boto3 library

## Environment Variables

- `COGNITO_REGION`: The AWS region where your Cognito User Pool is located.
- `COGNITO_USER_POOL_ID`: The ID of your Cognito User Pool.
- `COGNITO_APP_CLIENT_ID`: The App Client ID of your Cognito User Pool.

## Deployment

1. Create a virtual environment and install the required packages:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Package the Lambda function and dependencies:

```bash
cd $PROJECT_DIR
mkdir package
cp -r venv/lib/python3.8/site-packages/* package/
cp lambda_function.py package/
cd package
zip -r ../lambda_function.zip .
cd ..
```

3. Create the Lambda function in AWS Management Console, and upload the lambda_function.zip file.

4. Set the required environment variables in the AWS Lambda function configuration.

5. In the API Gateway, create a custom authorizer and select the Lambda function you created.

6. Attach the custom authorizer to the desired API routes.

## Usage 

https://your-api-id.execute-api.your-region.amazonaws.com/your-stage/your-resource?token=YOUR_ACCESS_TOKEN


If the access token is valid, the Lambda function will return a generated IAM policy to grant access to the requested API route. If the token is invalid or missing, the request will be denied.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

