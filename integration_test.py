#!/usr/bin/env python

import argparse

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

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=help)
parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='enable verbose mode', default=False)
parser.add_argument('--device-token', dest='device_token', help='device token we wish to use for testing', required=True)
parser.add_argument('--datastore', dest='datastore', help='URL of the encrypted datastore', default='http://localhost:8080')
parser.add_argument('--policystore', dest='policystore', help='URL of the policy store', default='http://localhost:8082')
parser.add_argument('--encoder', dest='encoder', help='URL of the stream encoder', default='http://localhost:8081')
args = parser.parse_args()

print(args)

