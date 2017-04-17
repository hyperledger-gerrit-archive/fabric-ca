# Simple load driver for Fabric CA
This is a simple load driver for Fabric CA. The driver can be configured using a JSON configuration file. Things like URL of the Fabric CA server, number of clients, number of requests per client, requests per second, test sequence, Fabric CA Client config, etc can be specified in the configuration file. You can look at the default configuraton file **testConfig.json** located in this directory.

## Steps
1. Set `registry.maxEnrollments` to at least 2 in the server configuration file
1. Make sure Fabric CA server is running and make note of the server URL, bootstrap user and password.
2. Modify the **testConfig.json** file
    * Modify the URL property. It is of the form : `<http|https>://<bootstrap user id>:<bootstrap password>@<hostname>:<port>`. Note that the bootstrap user must have revoker authority and must be affiliated with root of the affiliation tree, which is **""** or parent affiliation of the affiliations specified in the `affiliations` property
    * Change load properties like `numClients`, `numReqsPerClient`, `testSeq` properties as needed. `testSeq` property specifies the sequence of tests that are run in each iteration by a client. Each test has a `name` and optional `repeat` property, which specifies how many times to repeat the test in each iteration.
    * Change `affiliations` property. It specifies a list of affiliations to use in the test. Load driver will randomly select an affiliation from this list for each identity used in the test.
    * If you need TLS to be used to connect to the Fabric CA server, first make sure **https** protocol is used in the `URL` property. Next, set `tls.enabled` to true. Then, specify certificate file in the `tls.certfileslist` property.
    * Optionally, change the `tcertReq` property to specify payload for "get tcerts" requests.
    * Optionally, change the `revokeReq` property. Specify a random string for `id` property if you need to revoke an identity. If you need to revoke a ECert of an identity then specify a random string for `aki` or `serial` property
3. Run **runLoad.sh** script to start the load test. You can invoke this script with -B option to build the driver and run.
