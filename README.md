# DECODE integration test script

## Example

```bash
./integration_test.py --device-token=ab123ba --verbose
```

The above command attempts to create a policy, create a stream that applies
that policy. It then waits for 2 minutes trying to read encrypted data for
that policy from the datastore. If this is successful we then ensure we can
decrypt the data using Zenroom. Finally we attempt to delete the stream and
policy to avoid leaving test resources behind.

## CLI Interface

```bash
usage: integration_test.py [-h] [-v] --device-token DEVICE_TOKEN
                           [--datastore DATASTORE] [--policystore POLICYSTORE]
                           [--encoder ENCODER]

    Execute a series of integration tests against DECODE components in order to
    verify they are behaving as expected.  When executed this command runs the
    following sequence of steps:

        * create a policy and verify we can read this policy back from the policy
          store
        * create an encrypted stream for a device that applies this policy
        * read some data from the encrypted datastore for the policy
        * decrypt the data using zenroom and display this to the screen
        * clean up all created resources

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         enable verbose mode
  --device-token DEVICE_TOKEN
                        device token we wish to use for testing
  --datastore DATASTORE
                        URL of the encrypted datastore
  --policystore POLICYSTORE
                        URL of the policy store
  --encoder ENCODER     URL of the stream encoder
```