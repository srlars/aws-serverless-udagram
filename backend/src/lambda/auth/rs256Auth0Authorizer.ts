import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIJRU7egnjW0Sg1MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAMTEGRldi05OS5hdXRoMC5jb20wHhcNMjAwNDA1MTE0MTQyWhcNMzMxMjEzMTE0
MTQyWjAbMRkwFwYDVQQDExBkZXYtOTkuYXV0aDAuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAyBfOsiLM/AXqg/nr7b81EUNvIAr1dzJnRpqLLVxS
GBuk6+WKDlt9e9Q4pO1Qlzum81VASxcHsN4H/mENd+v74TYKHGRwV+Tha7U/RmZX
ugMzdLxvfzZYBilWKuppmjjfa9bf4JtwSO97riu3TLajqusl/L+N5SwvVG6hF4mb
Bf85Fa7fsN1QnoEQAz0tK4MyV7RRON1/OZJJGeTLA9N7J2cAYMorzmZc1BNBmPiS
BP9Bzn86v58osxrX7xO1P9u6YwAkXp8UqQB4Y2CUeycaCwWQpc5ZEI6hUQI+fxDY
n/z5AkcgDJIADu0jtdIawtg6aVkxXaphWs4HuFvxxnss3wIDAQABo0IwQDAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTXFLx396aPJXTCEl+JVQOqQRfRYzAOBgNV
HQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAL5yd17Rn0Vr6sA/LJgTUh+c
40QWTjx1mr97vCP0UbEBUH8ogoaR8tLYMfpOtfOS9qsn5+Wl7q2lqI1CiXFKOxeL
LxWy5beBYij56vBhCvMEuev53EA+giTxABzjRtYyLN7m6/XwQmXxgdTUFj9HgGI2
tIXpGx6kh90YfEO4YNNsVTaJU6En0cc8A4orjHhBYNr9hoa7O/SsUE8SjPQmANg9
OgcC+MNFGPB1zK4o+PWis7KwKNU0CKgankyufe0JD+8H4BWA7RZpML9NIzSFR53G
ZelcugNg49fzHoApJOzjUAAarzeYmMOH7lp7SQy7WNPoL6XcuutGNWW4ZQikyN8=
-----END CERTIFICATE-----`

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
