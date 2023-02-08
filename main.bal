import ballerina/http;
import ballerina/jwt;

service / on new http:Listener(8080) {

    resource function get hello(http:Request request) returns jwt:Payload | UnauthorizedErrorCode{

        // JWT Validator config configured with the Issuer and the Signature config which points at the JWKS URL
        jwt:ValidatorConfig validatorConfig = {
            clockSkew: 60,
            signatureConfig: {
                jwksConfig: {   
                    url: "https://gateway.e1-us-east-azure.choreoapis.dev/.wellknown/jwks",
                    cacheConfig: { 
                        capacity: 10,
                        evictionFactor: 0.2,
                        defaultMaxAge: 0.5,
                        cleanupInterval: 1
                     }
                }
            }
        };
        
        var jwt = request.getHeader("x-jwt-assertion");


        if !(jwt is string) {
            UnauthorizedErrorCode err = {body: {errmsg: "JWT Not provided in header"}};
            return err;
        }


        // Validating the JWT based on its signature and expiration time
        jwt:Payload|jwt:Error result = jwt:validate(jwt, validatorConfig);

        if (result is jwt:Error) {
            UnauthorizedErrorCode err = {body: {errmsg: result.message()}};
            return err;
        }
        
        return result;
    }
}

public type UnauthorizedErrorCode record {|
   *http:Unauthorized;
   ErrorMsg body;
|};

public type HeaderNotFoundErrorCode record {|
   *http:BadRequest;
   ErrorMsg body;
|};

public type ErrorMsg record {|
   string errmsg;
|};
