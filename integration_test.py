#!/usr/bin/env python

import argparse
import logging
import requests
import sys
import pprint
from datetime import datetime, timedelta
import maya
import time
import json
import base64
from zenroom import zenroom

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

POLICYSTORE_PREFIX = '/twirp/decode.iot.policystore.PolicyStore/'
ENCODER_PREFIX = '/twirp/decode.iot.encoder.Encoder/'
DATASTORE_PREFIX = '/twirp/decode.iot.datastore.Datastore/'


def main():
    help = """
    Execute a series of integration tests against DECODE components in order to
    verify they are behaving as expected.  When executed this command runs the
    following sequence of steps:

        * create a policy and verify we can read this policy back from the policy
          store
        * create an encrypted stream for a device that applies this policy
        * read some data from the encrypted datastore for the policy
        * decrypt the data using zenroom and display this to the screen
        * clean up all created resources"""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter, description=help)
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        dest='verbose',
        help='enable verbose mode',
        default=False)
    parser.add_argument(
        '--device-token',
        dest='device_token',
        help='device token we wish to use for testing',
        required=True)
    parser.add_argument(
        '--datastore',
        dest='datastore',
        help='URL of the encrypted datastore',
        default='http://localhost:8080')
    parser.add_argument(
        '--policystore',
        dest='policystore',
        help='URL of the policy store',
        default='http://localhost:8082')
    parser.add_argument(
        '--encoder',
        dest='encoder',
        help='URL of the stream encoder',
        default='http://localhost:8081')
    parser.set_defaults(func=run)
    args = parser.parse_args()
    args.func(args)


def run(args):
    """This is the list of operations this integration test performs.

    Within this test script, we create a policy with a generated key/pair using
    Zenroom, we then verify that we can read back the policy from the
    policystore, then create an encrypted stream on the stream encoder. We then
    verify that we can read values for the policy back from the datastore, and
    finally we verify that are able to decrypt the written data again using
    Zenroom.

    Once the test completes we then try and delete all created resources."""

    logging.info('Starting integration test')

    # read configuration from our args
    verbose = args.verbose
    device_token = args.device_token
    policystore_url = args.policystore
    encoder_url = args.encoder
    datastore_url = args.datastore

    # create a policy
    policy_credentials = create_policy(policystore_url,
                                       create_policy_request(), verbose)

    # read the policies back from the policystore
    policies = list_policies(policystore_url, verbose)

    # search for our created policy in the returned list
    for p in policies['policies']:
        if policy_credentials['policy_id'] == p['policy_id']:
            policy = p
            break
    else:
        # clean up the previously created policy
        delete_policy(policystore_url, policy_credentials, verbose)
        sys.exit(
            "Unable to find created policy in list read from policy store")

    # create a stream
    stream_credentials = create_stream(
        encoder_url, create_stream_request(device_token, policy), verbose)

    #  read some data from the datastore for the policy
    read_request = create_read_request(policy)
    success = read_data(datastore_url, read_request, verbose)

    # delete the created stream
    delete_stream(encoder_url, stream_credentials, verbose)

    # delete the created policy
    delete_policy(policystore_url, policy_credentials, verbose)

    if success:
        logging.info('SUCCESS: All tests succeeded')
    else:
        sys.exit('FAILED: Failed to read data')


def create_policy_request():
    """Return a static configuration for a policy"""
    return {
        'public_key':
        r'BBLewg4VqLR38b38daE7Fj\/uhr543uGrEpyoPFgmFZK6EZ9g2XdK\/i65RrSJ6sJ96aXD3DJHY3Me2GJQO9\/ifjE=',
        'label':
        'Integration Test Policy',
        'operations': [{
            'sensor_id': 10,
            'action': 'SHARE',
        }, {
            'sensor_id': 53,
            'action': 'BIN',
            'bins': [30.0, 60.0, 90.0]
        }, {
            'sensor_id': 55,
            'action': 'MOVING_AVG',
            'interval': 300
        }]
    }


def create_stream_request(device_token, policy):
    """Return the json object we must send to create a stream"""
    return {
        'device_token':
        device_token,
        'policy_id':
        policy['policy_id'],
        'recipient_public_key':
        r'BBLewg4VqLR38b38daE7Fj\/uhr543uGrEpyoPFgmFZK6EZ9g2XdK\/i65RrSJ6sJ96aXD3DJHY3Me2GJQO9\/ifjE=',
        'location': {
            'longitude': 2.156746,
            'latitude': 41.401642
        },
        'exposure':
        'INDOOR',
        'operations':
        policy['operations']
    }


def create_read_request(policy):
    """Return the json object for a read request"""
    start_time = maya.MayaDT.from_datetime(datetime.now() -
                                           timedelta(minutes=15)).rfc3339()

    return {'policy_id': policy['policy_id'], 'start_time': start_time}


def headers():
    """Return static headers that all requests need"""
    return {
        'user-agent': 'integration-tester',
        'content-type': 'application/json',
    }


def create_policy(policystore_url, create_policy_request, verbose):
    """Create a new entitlement policy.

    This sends a request to the policystore to create a new policy using the
    static configuration defined previously in this script."""

    if verbose:
        logging.info('Creating policy')
        pprint.pprint(create_policy_request)

    create_url = policystore_url + POLICYSTORE_PREFIX + 'CreateEntitlementPolicy'

    r = requests.post(
        create_url, headers=headers(), json=create_policy_request)
    if r.status_code != 200:
        logging.error(f'ERROR: Unexpected response: {r.status_code}')
        pprint.pprint(r.json())

        sys.exit('Failed to create policy')

    resp = r.json()

    logging.info(
        f'SUCCESS: Created policy - ID: {resp["policy_id"]}, Token: {resp["token"]}'
    )

    return resp


def delete_policy(policystore_url, policy_credentials, verbose):
    """Delete existing entitlement policy.

    This sends a request to the policystore to delete an existing policy. This
    requires the use of the generated ID and token from a previous create
    call."""

    if verbose:
        logging.info('Deleting policy')
        pprint.pprint(policy_credentials)

    delete_url = policystore_url + POLICYSTORE_PREFIX + 'DeleteEntitlementPolicy'

    r = requests.post(delete_url, headers=headers(), json=policy_credentials)
    if r.status_code != 200:
        logging.error(f'ERROR: Unexpected response: {r.status_code}')
        pprint.pprint(r.json())
        sys.exit('Failed to delete policy')

    logging.info('SUCCESS: Deleted policy')


def list_policies(policystore_url, verbose):
    """List available entitlement policies

    This sends a request to the policystore to read a list of all available
    policies."""

    if verbose:
        logging.info('Listing policies')

    list_url = policystore_url + POLICYSTORE_PREFIX + 'ListEntitlementPolicies'

    r = requests.post(list_url, headers=headers(), json={})
    if r.status_code != 200:
        logging.error(f'ERROR: Unexpected response: {r.status_code}')
        pprint.pprint(r.json())
        sys.exit('Failed to list policies')

    logging.info('SUCCESS: Listed policies')

    resp = r.json()

    if verbose:
        logging.info('Policies retrieved')
        pprint.pprint(resp)

    return resp


def create_stream(encoder_url, request, verbose):
    """Create a new encoded stream"""

    if verbose:
        logging.info('Creating encoded stream')
        pprint.pprint(request)

    create_url = encoder_url + ENCODER_PREFIX + 'CreateStream'

    r = requests.post(create_url, headers=headers(), json=request)
    if r.status_code != 200:
        logging.error(f'ERROR: Unexpected response: {r.status_code}')
        pprint.pprint(r.json())

        sys.exit('Failed to create policy')

    resp = r.json()

    logging.info(
        f'SUCCESS: Created stream - ID: {resp["stream_uid"]}, Token: {resp["token"]}'
    )

    return resp


def delete_stream(encoder_url, stream_credentials, verbose):
    """Delete a stream on being given the credentials for that stream"""

    if verbose:
        logging.info('Deleting stream')
        pprint.pprint(stream_credentials)

    delete_url = encoder_url + ENCODER_PREFIX + 'DeleteStream'

    r = requests.post(delete_url, headers=headers(), json=stream_credentials)
    if r.status_code != 200:
        logging.error(f'ERROR: Unexpected response: {r.status_code}')
        pprint.pprint(r.json())
        sys.exit('Failed to delete stream')

    logging.info('SUCCESS: Stream deleted')


def read_data(datastore_url, read_request, verbose):
    """Attempt to read encrypted data from the datastore"""

    logging.info('Checking if data is available')

    if verbose:
        pprint.pprint(read_request)

    read_url = datastore_url + DATASTORE_PREFIX + 'ReadData'

    timeout = time.time() + 60 * 2  # 2 minutes from now

    while True:
        print('.', end='', flush=True)
        r = requests.post(read_url, headers=headers(), json=read_request)
        if r.status_code != 200:
            logging.error(f'ERROR: Unexpected response: {r.status_code}')
            pprint.pprint(r.json())
            return False

        resp = r.json()

        if verbose:
            pprint.pprint(resp)

        if len(resp['events']) > 0:
            print('')
            logging.info('SUCCESS: Read encrypted data')
            return decrypt_data(resp['events'][0], verbose)

        if time.time() > timeout:
            print('')
            logging.warning(
                'ERROR: Failed to read any data for the policy. Please check device token and try again'
            )
            return False

        time.sleep(10)

    return True


def decrypt_data(event, verbose):
    keys = json.dumps({
        'community_seckey':
        r'D19GsDTGjLBX23J281SNpXWUdu+oL6hdAJ0Zh6IrRHA='
    })

    with open('decrypt.lua') as file:
        script = file.read()

    decoded = base64.decodebytes(event['data'].encode())
    result = zenroom.execute(script.encode(), keys=keys.encode(), data=decoded)
    packet = json.loads(result)
    data = json.loads(packet['data'])

    if verbose:
        logging.info("Decrypted data")
        pprint.pprint(data)

    # verify the presence of an expected key
    if 'token' in data:
        logging.info('SUCCESS: Decrypted packet correctly')
        return True
    else:
        logging.info('ERROR: Unexpected content after decryption')
        pprint.pprint(data)
        return False


if __name__ == "__main__":
    main()
