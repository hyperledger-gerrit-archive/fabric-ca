# Fabric CA Developer's Guide

This is the Developer's Guide for Fabric CA, which is a Certificate Authority for Hyperledger Fabric.

See [User's Guide for Fabric CA](https://hyperledger-fabric.readthedocs.io/en/latest/Setup/ca-setup.html) for user's information.

## Prerequisites

* Go 1.7+ installation or later
* **GOPATH** environment variable is set correctly
* docker version 17.03 or later
* docker-compose version 1.11 or later
* A linux foundation ID  (see [create a linux foundation ID](https://identity.linuxfoundation.org/))


## Contribution guidelines

You are welcome to contribute to fabric CA!
   
The following are guidelines to follow when contributing:

1. See the general information about [contributing to fabric](http://hyperledger-fabric.readthedocs.io/en/latest/abstract_v1.html?highlight=jira#how-to-contribute).

2. To set up your development environment and doing other common development tasks, see [bash_profile](https://github.com/hyperledger/fabric-ca/blob/master/scripts/bash_profile).  This contains variables and functions which can be copied directly into your `.bash_profile` file.  Even if you do not use bash, you should still find the functions instructive.  For example:  
   a. **clone** - pulls the latest fabric-ca code from gerrit and places it based on your GOPATH setting  
   b. **cdr** - cd to the fabric-ca repository root, which is equivalent to "cd $GOPATH/src/github.com/hyperledger/fabric-ca"  
   c. **gencov** - generates a test coverage report  
   d. **push** - pushes your current commits to gerrit after running the unit tests successfully

3. To run the unit tests directly:

   ```
   # cdr
   # make unit-tests
   ```
   
   The test coverage for each package must be 75% or greater.  If this fails because there is insufficient test coverage, then you can run `gencov` to get a coverage report to see what code is not being tested.   Once you have added additional test cases, you can run `go test -cover` in the appropriate package to see the current coverage level.
   
4. To commit your changes:

   ```
   git commit -s
   ```
   
   This puts you into an editor.  
   On the 1st line, put a brief description.  
   Then skip a line and put the link to a jira item associated with your change.  
   Each change set must have a jira item in the commit message.  
   Also add additional comments which would be helpful to those reviewing your changes.
   
5. Push your changes with the `push` command.

6. Monitor the status of your change set in [gerritt](https://gerrit.hyperledger.org).

## Package overview

1. **cmd/fabric-ca-server** contains the main for the fabric-ca-server command.
2. **cmd/fabric-ca-client** contains the main for the fabric-ca-client command.
3. **lib** contains most of the code.  
   a) **server.go** contains the main Server object, which is configured by **serverconfig.go**.  
   b) **client.go** contains the main Client object, which is configured by **clientconfig.go**.  
4. **lib/csp** contains some functions related to the Crypto Service Provider.
5. **lib/dbutil** contains database utility functions.
6. **lib/ldap** contains LDAP client code.
7. **lib/spi** contains Service Provider Interface code for the user registry.
8. **lib/tls** contains TLS related code for server and client.
9. **util** contains various utility functions.

## Additional info

### FVT

See [FVT tests](scripts/fvt/README.md) for information on functional verification test cases.

    
 