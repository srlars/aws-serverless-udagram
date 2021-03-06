import {
  APIGatewayProxyHandler,
  APIGatewayProxyEvent,
  APIGatewayProxyResult
} from 'aws-lambda'
import 'source-map-support/register'
import { getAllGroups } from '../../businessLogic/groups'

export const handler: APIGatewayProxyHandler = async (
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
  console.log('Processing event: ', event)

  const groups = await getAllGroups()

  return {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*'
    },
    body: JSON.stringify({
      items: groups
    })
  }
}

// Old Code before ports and adapters architecture split

// import {
//   APIGatewayProxyHandler,
//   APIGatewayProxyEvent,
//   APIGatewayProxyResult
// } from 'aws-lambda'
// import 'source-map-support/register'
// import * as AWS from 'aws-sdk'

// const docClient = new AWS.DynamoDB.DocumentClient()

// const groupsTable = process.env.GROUPS_TABLE

// export const handler: APIGatewayProxyHandler = async (
//   event: APIGatewayProxyEvent
// ): Promise<APIGatewayProxyResult> => {
//   console.log('Processing event: ', event)

//   const result = await docClient
//     .scan({
//       TableName: groupsTable
//     })
//     .promise()

//   const items = result.Items

//   return {
//     statusCode: 200,
//     headers: {
//       'Access-Control-Allow-Origin': '*'
//     },
//     body: JSON.stringify({
//       items
//     })
//   }
// }
