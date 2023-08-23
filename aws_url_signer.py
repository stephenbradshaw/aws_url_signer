#!/usr/bin/env python
import sys
import os
import datetime
import argparse
import hashlib
import hmac
import urllib.parse
import json 
import logging
from typing import Union
from logging import Logger
from botocore import loaders # we use boto to get service names and API versions only


def check_ipython() -> bool:
    '''Returns True if script is running in interactive iPython shell'''
    try:
        get_ipython()
        return True
    except NameError:
        return False


class MyParser(argparse.ArgumentParser):
    '''Custom argument parser'''
    def error(self, message: str):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


def create_logger(loglevel: str, name: str) -> Logger:
    '''Create a custom logger instance'''
    logger = logging.getLogger(name)
    logger.setLevel(loglevel)
    handler = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger



def parse_export(instring: str) -> str:
    '''Helper function to extract instance credential information to export commands from JSON response'''
    instr = urllib.parse.unquote(instring)
    data = json.loads(instr)
    out = 'export AWS_ACCESS_KEY_ID="{}"\n'.format(data['AccessKeyId'])
    out+= 'export AWS_SECRET_ACCESS_KEY="{}"\n'.format(data['SecretAccessKey'])
    out+= 'export AWS_SESSION_TOKEN="{}"\n'.format(data['Token'])

    return out



# API documentation: https://docs.aws.amazon.com/index.html

# implements sigv4
# See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

class AWSApiUrlGenerator:

    def __init__(self, access_key: str, secret_key: str, session_token: str=None, link_expiry: int=180, logger: Logger=None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.link_expiry = link_expiry
        self.sv = self.get_service_versions()
        # put service in region_bound list if <service>.amazonaws.com for service will not work for us-east-1
        # put service in non_canonical_token list if the session token is NOT used in signature calculation
        # default_version is the mandatory API version string for the service
        self.region_bound_services = [
            'ssm'
        ]
        self.non_canonical_token_services = []
        self.service_info = {a : {'default_version': self.sv[a], 'canonical_token': a not in self.non_canonical_token_services, 'region_bound': a in self.region_bound_services} for a in self.sv.keys()}
        if logger:
            self.logger = logger 
        else:
            self.logger = logging


    def tci(self, parent_key: str, input: Union[list, dict, str, int]) -> dict:
        '''Recursive helper function for type converting parameters'''
        out = {}
        if isinstance(input, list):
            vcounter = 1
            for value in input:
                pk = '{}.Values.{}'.format(parent_key, vcounter)
                result = self.tci(pk, value)
                out = {**out, **result}
                vcounter += 1
        elif isinstance(input, dict):
            kcounter = 1
            for key in input.keys():
                kn = '{}.Entry.{}'.format(parent_key, kcounter)
                out['{}.Name'.format(kn)] =  key
                result = self.tci('{}.Value'.format(kn), input[key])
                out = {**out, **result}
                kcounter += 1
        else:
            return {parent_key: input}
        return out


    def type_convertor(self, input: dict) -> dict:
        '''Convert parameters to GET API friendly format'''
        out = {}
        for key in input:
            result = self.tci(key, input[key])
            out = {**out, **result}
        return out
    

    def get_service_versions(self) -> dict:
        '''Get a dictionary of AWS services and API version values from botocore'''
        out = {}
        myloader = loaders.Loader()
        for service in myloader.list_available_services('service-2'):
            out[service] = myloader.determine_latest_version(service, 'service-2')
        return out


    def get_host_for_region(self, service: str, region: str) -> str:
        '''Get the API host for the AWS API service based on the selected region'''
        if service in self.service_info and self.service_info[service].get('region_bound'):
            return '{}.{}.amazonaws.com'.format(service, region)
        else:
            return '{}.amazonaws.com'.format(service) if region == 'us-east-1' else '{}.{}.amazonaws.com'.format(service, region)


    # Key derivation functions. See:
    # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    def sign(self, key: bytes, msg: str) -> bytes:
        '''HMAC Signing function'''
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def get_signature_key(self, key: str, dateStamp: str, regionName: str, serviceName: str) -> bytes:
        '''Get the URL signing key'''
        kDate = self.sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'aws4_request')
        return kSigning


    #When you add the X-Amz-Security-Token parameter to the query string, some services require that you include this parameter in the canonical (signed) request.
    # For other services, you add this parameter at the end, after you calculate the signature. For details, see the API reference documentation for that service.
    def create_aws_api_url(self, service: str, parameters: dict, host: str, region: str, endpoint: str, canonical_token: bool=True) -> str:
        '''Create a signed URL for a given API endpoint host'''
        t = datetime.datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ') # Format date as YYYYMMDD'T'HHMMSS'Z'
        datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
        params = {
            'X-Amz-Algorithm': algorithm,
            'X-Amz-Credential': urllib.parse.quote_plus(self.access_key + '/' + credential_scope),
            'X-Amz-Date' : amz_date,
            'X-Amz-Expires' : self.link_expiry,
            'X-Amz-SignedHeaders': 'host'
        }

        if self.session_token and canonical_token:
            params['X-Amz-Security-Token'] = urllib.parse.quote_plus(self.session_token)

        modified_parameters = self.type_convertor(parameters)
        self.logger.debug('Parsed Url Parameters: {}'.format(json.dumps(modified_parameters)))
        enc_params = {urllib.parse.quote(a): urllib.parse.quote(modified_parameters[a], safe='') for a in modified_parameters}

        qp = {**enc_params, **params}
        canonical_querystring = '&'.join(['{}={}'.format(a, qp[a]) for a in sorted(qp.keys())])

        if service != 's3':
            payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
        else:
            payload_hash = 'UNSIGNED-PAYLOAD' # yudodis - s3 special for some reason

        canonical_request = 'GET\n{}\n{}\nhost:{}\n\nhost\n{}'.format('/', canonical_querystring, host, payload_hash)
        string_to_sign = '\n'.join([algorithm, amz_date, credential_scope, hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()])

        sep = '=========='
        self.logger.debug('Digest: {}\n'.format(hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()))
        self.logger.debug('Canonical Request:\n{}\n{}\n{}\n'.format(sep, canonical_request, sep))
        self.logger.debug('String to sign:\n{}\n{}\n{}\n'.format(sep, string_to_sign, sep))

        signing_key = self.get_signature_key(self.secret_key, datestamp, region, service)
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()
        canonical_querystring += '&X-Amz-Signature=' + signature

        if self.session_token and not canonical_token:
            canonical_querystring += '&X-Amz-Security-Token=' + urllib.parse.quote_plus(self.session_token)

        return endpoint + "/?" + canonical_querystring


    def create_service_url(self, service: str, action: str, parameters: dict={}, region: str='us-east-1', version: str=None, canonical_token: bool=None) -> str:
        '''External interface for creating a signed GET URL for a given API call'''
        host = self.get_host_for_region(service, region)
        version = version if version else self.service_info[service].get('default_version') if service in self.service_info else None
        if not version:
            raise Exception('A default version for service type "{}" was not found, please provide a version stamp'.format(service))
        if not isinstance(canonical_token, type(None)):
            canonical_token = canonical_token
        elif service in self.service_info and 'canonical_token' in self.service_info[service]:
            canonical_token = self.service_info[service]['canonical_token']
        default_params = {'Action': action, 'Version': version}
        return self.create_aws_api_url(service, {**default_params, **parameters} , host, region, 'https://{}'.format(host), canonical_token)


def command_line():
    parser = MyParser()
    input_arg_group = parser.add_argument_group('API Operation')
    input_arg_group.add_argument('-service', type=str, required=True, help='AWS service for the API call')
    input_arg_group.add_argument('-action', type=str, required=True, help='AWS action for the API call')
    input_arg_group.add_argument('-region', type=str, default='us-east-1', help='AWS region for operation')
    input_arg_group.add_argument('-parameters', type=str, default='{}', help='AWS parameters for the API call, JSON encoded')

    output_arg_group = parser.add_argument_group('Output')
    output_arg_group.add_argument('-link-expiry', type=int, default=180, help='Link expiry time in seconds - default 180')
    output_arg_group.add_argument('-loglevel', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='WARNING', help='Set logging level')

    auth_arg_group = parser.add_argument_group('Authentication')
    mgroup_schema = auth_arg_group.add_mutually_exclusive_group()
    mgroup_schema.add_argument('-environment', action='store_true', help='Get the credentials from AWS environment variables')
    mgroup_schema.add_argument('-access-key', type=str, help='AWS access key ID')
    auth_arg_group.add_argument('-secret-key', type=str, help='AWS secret access key')
    auth_arg_group.add_argument('-session-token', type=str, help='AWS session token')

    args = parser.parse_args()

    logger = create_logger(args.loglevel, 'AWS URL Signer')

    if args.environment:
        access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        session_token = os.environ.get('AWS_SESSION_TOKEN')
        if args.secret_key or args.session_token:
            logger.warning('Secret key and session token values provided as parameters ignored due to environment variable setting.')
    else:
        access_key = args.access_key
        secret_key = args.secret_key
        session_token = args.session_token


    if access_key is None or secret_key is None:
        print('No access key is configured!\n\n')
        parser.print_help()
        sys.exit()

    api = AWSApiUrlGenerator(access_key, secret_key, session_token, link_expiry=args.link_expiry, logger=logger)

    service = args.service
    if service not in api.sv:
        print('Service {} not in supported service list'.format())
    region = args.region
    action = args.action
    try:
        parameters = json.loads(args.parameters)
    except Exception as e:
        print('There was an error in JSON decoding the parameters provided.\n')
        print(e)
        sys.exit(1)


    request_url = api.create_service_url(service, action, region=region, parameters=parameters)

    print(request_url)
    

    
if __name__ == "__main__":
    # execute only if run as a script, helpful if script needs to be debugged
    
    if not check_ipython():
        command_line()



# Some examples of using the API in Python code

## Setup
#from aws_url_signer import AWSApiUrlGenerator
#api = AWSApiUrlGenerator(access_key, secret_key, session_token)

# Make some API calls
#request_url = api.create_service_url('s3', 'ListBuckets')
#request_url = api.create_service_url('iam', 'ListUsers')
#request_url = api.create_service_url('ec2', 'DescribeRegions')
#request_url = api.create_service_url('ec2', 'DescribeInstances', parameters = {'MaxResults': '2'}, region='ap-southeast-2')
#request_url = api.create_service_url('ec2', 'DescribeInstances', parameters = {'MaxResults': '5'} )
#request_url = api.create_service_url('sts', 'GetCallerIdentity')
#request_url = api.create_service_url('ssm', 'DescribeInstanceInformation', region='ap-southeast-2')
#request_url = api.create_service_url('ssm', 'ListDocuments', region='ap-southeast-2')
#request_url = api.create_service_url('ssm', 'ListCommands', parameters = {'MaxResults': '5'}, region='ap-southeast-2')
#request_url = api.create_service_url('ssm', 'ListCommands', parameters = {'MaxResults': '5', 'InstanceIds': 'i-xxxxxxxxxxxxxxxxx'}, region='ap-southeast-2')

#params = {"InstanceIds": ["i-xxxxxxxxxxxxxxxxx"], "DocumentName": "AWS-RunShellScript", "Parameters": {"commands": ["echo 1 > /tmp/123"]}} 
#request_url = api.create_service_url('ssm', 'SendCommand', parameters = params, region='ap-southeast-2')