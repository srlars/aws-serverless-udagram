## Deployment to AWS

1. Install node modules:
   `npm install`
2. Configure [Auth0](https://auth0.com/)application for authentication and authorisation and set 'domain' and 'clientId' in client/src/config.
3. Deploy to AWS:
   `sls deploy -v`
4. Set 'apiId' of created API Gateway instance to client/src/config.
5. Set 'auth0Secret' in AWS Secrets Manager.

6. Canary deployment, inividual packaging of AWS Lambda functions, AWS X-Ray, offline testing via local dynamodb and serverless-offline can be implemented / uncommented via the serverless.yaml file.
