import ballerina/http;
import ballerina/jwt;

service / on new http:Listener(8080) {

    resource function get hello(http:Request request) returns string|error { // send my own status codes
        
        // JWT Validator config configured with the Issuer and the Signature config which points at the JWKS URL
        jwt:ValidatorConfig validatorConfig = {
        issuer: "wso2.org/products/am",
        clockSkew: 60,
        signatureConfig: {
            jwksConfig: {url: "https://gateway.e1-us-east-azure.preview-dv.choreoapis.dev/.wellknown/jwks", cacheConfig: {}}
        }
        };
        var jwt = request.getHeader("x-jwt-assertion");

        if !(jwt is string) {
            return error("JWT header not available");
            
        }
        // Validating the JWT based on its signature and expiration time
        jwt:Payload|jwt:Error result = check jwt:validate(jwt, validatorConfig);

        if result is jwt:Error {
            return error("Failed to authenticate " + result.message());
        }
        
        return result.toBalString();
    }
}