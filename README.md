# aws_url_signer

POC tool to create signed AWS API GET requests to bypass Guard Duty alerting of off-instance credential use via SSRF

# What?

AWS has a Guard Duty alert to advise when an AWS instance credential is used outside of the instance itself. This will give you as the account owner a heads up when the instance credentials are stolen using a vulnerability like a Server Side Request Forgery (SSRF) from the Metadata URL and then subsequently used from the attackers system.

This alerting relies on the instance credential being taken off the owning host and then used to make an AWS API query from a machine that is not in the associated AWS account. This is a common circumstance when instance credentials are comprimised via SSRF - attacker gets the instance creds from the metadata service on a vulnerable EC2 host, configures those credentials locally on their own local machine, and then calls the AWS API from there to try and further compromise the associated AWS account.  

Even though its not obviously exposed in the various client libraries (except for S3 signed URLs) however, it is possible to make general requests of the AWS API using HTTP GET requests. This approach enables you to create signed URLs to query the AWS API, send them via the same mechanism by which you compromised the credentials in the first place (e.g. SSRF), and bypass the Guard Duty alerting. This is because AWS API calls made in this way are not being made outside of the AWS account owning the credential - because you make the API call by sending the URL through the SSRF, from the perspective of the API server they are coming from the same EC2 instance that owns that credential.

There is [another approach](https://github.com/Frichetten/SneakyEndpoints) available to also bypass these alerts, but in comparison this method requires much less infrastructure and setup and can support more services. As a downside however, this approach prevents you from being able to use existing offensive tools that work with compromised credentials, requires a potentially greater understanding of the AWS API, and may be limited by the retrieval capabilities of the SSRF used.


# Usage

This tool is a proof of concept that implements the AWS v4 API signing algorithm for GET URLS. It has very minimal requirements, using `botocore` just to get the list of available services and API versions. 

It has a simple command line interface to run standalone and can also be imported as a module into other Python 3 code to allow it to be more easily used with other exploit code (e.g. SSRF, XXE, etc).

In the very simplest form, you can set your stolen credentials into the standard environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`) and call the tool like the following to run the `GetCallerIdentity` action for the `sts` service.

```
./aws_url_signer.py -environment -service sts -action GetCallerIdentity
```

This will spit out a signed URL, with a 180 second expiry time, that can be sent in your exploit to make the associated API call. The response will tell you about the  "caller Identity" of the credential you have.

You can do more complex stuff by sending parameters to the call as a JSON encoded string.

The following example uses SSM to generate a URL to remotely execute code against a managed Linux instance `i-xxxxxxxxxxxxxxxxx` in the account.

```
./aws_url_signer.py -environment -service ssm -action SendCommand -region ap-southeast-2 -parameters '{"InstanceIds": ["i-xxxxxxxxxxxxxxxxx"], "DocumentName": "AWS-RunShellScript", "Parameters": {"commands": ["curl http://test.site/123"]}}'
```


You can also stick the .py file in your Python path and use it in your code like so.

```
from aws_url_signer import AWSApiUrlGenerator

api = AWSApiUrlGenerator(access_key, secret_key, session_token)
request_url = api.create_service_url('s3', 'ListBuckets', region='ap-southeast-2')

```

To a large extent you do need to know the AWS API to be able to use this in a useful way, although I have provided some of the examples I have personally tested below.  To some extent you can use it in a similar way to the [AWS cli](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/index.html), but the parameter format will be different in a number of cases, so you can combine it with the general API documentation [here](https://docs.aws.amazon.com/index.html). Find the service you want, and take what would normally be sent in a POST request for a particular API call and supply it JSON encoded to the `parameters` option, and it _SHOULD_ work.


# "Legacy" APIs

Some of the AWS API endpoints such as Route53 and CloudFront are using what I'm referring to as a "legacy" API calling format, which is different from the approach used by a lot of other AWS APIs, and hence results in a different looking URL. 

To explain by example, lets look at the [ListDistributions](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListDistributions.html) action for CloudFront.

According to the documentation, tt uses a syntax like so.
```
GET /2020-05-31/distribution?Marker=Marker&MaxItems=MaxItems HTTP/1.1
```

In this case, the API version `2020-05-31` is included as a path parameter in the URL, instead of a query parameter where it is for most other calls, and the action of `ListDistributions` is no where to be found. Instead there is a path parameter of `distribution` immediately following the version which is serving as the action.

I have added edge case code for the services Im aware of that use this calling convention into the tool. You can create a signed URL for this particular call like so - using the value of the **path** parameter immediately following the version as your `action`. The API version will be automatically extracted from botocore and filled in by the tool.

```
./aws_url_signer.py -environment -service cloudfront -action distribution
```

The calling convention here also uses optional query parameters `Marker` and `MaxItems`. The `parameters` command line option of the tool can be used as with the other non legacy calling convention to specify these.


For API calls following this approach that use additional **path** parameters **after** the one immediately following the version, I have added a `path-parameters` command line option you can use to provide these. It takes an **ordered** comma seperated list of path parameter values to add to the URL.

Take [GetDistribution](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetDistribution.html) as an example. It provides the `ID` of the distribution to retrieve as a path parameter immediately following the **"action"** of `distribution`.

```
GET /2020-05-31/distribution/<Id> HTTP/1.1
```

If I wanted to call this using `E1XXXXXXXXXXXX` as the ID value, I would call the tool like so:

```
./aws_url_signer.py -environment -service cloudfront -action distribution -path-parameters E1XXXXXXXXXXXX
```

As another example, imagine a theoretical API call with action `whatever` with two **ordered** URL **path** parameters `param1` and `param2`.

```
GET /2020-05-31/whatever/<param1>/<param2> HTTP/1.1
```

This would be called like so:

```
./aws_url_signer.py -environment -service cloudfront -action whatever -path-parameters param1,param2
```

So far Ive only added code for the Route53 and CloudFront services to allow for this "legacy" calling convention, if you find any others that do this that Ive missed then please raise an Issue or PR (services using this convention are in a list in the constructor of the API object).


# Warning 

This tool creates a signed https URL that can perform AWS API calls as the compromised user. Standard warnings apply for leaving the URL where others can see it or having it leaked in logs or other intermediate devices. The URLs do timeout after a default period of 180 seconds, so the URLs do have a limited lifetime.


# Alpha code

This should be considered Alpha quality code.

At the time of writing there are 313 services currently supported in the AWS API - I have only tested a small fraction of them that I personally needed to prove impact of SSRF related vulnerabilities.

While the AWS v4 API signing process is more or less standard across the various supported services, there are differences in where regional endpoints sit, and the specific nature of the signed payload and signing process for some services. This could mean that some services I have not specifically tested may not work, but I think many probably will.

The process by which more complex parameter structures are converted into GET compatible versions is also rather unique. It's possible my code to convert parameters from a standard JSON compatible format is wrong or incomplete, and this will only become clear once someone tries to send parameters more complex than the SSM code execution example above.

Feel free to raise issues or PRs if you find any problems.


# Examples

Here are some examples of running the command line version of the tool. There are some additional commented examples for using the module in code in the source.
```
./aws_url_signer.py -environment -service iam -action ListUsers
./aws_url_signer.py -environment -service sts -action GetCallerIdentity
./aws_url_signer.py -region ap-southeast-2 -environment -service ssm -action DescribeInstanceInformation 
./aws_url_signer.py -region ap-southeast-2 -environment -service ec2 -action DescribeInstances -parameters '{"MaxResults": "5"}'
./aws_url_signer.py -region ap-southeast-2 -environment -service s3 -action ListBuckets
```
