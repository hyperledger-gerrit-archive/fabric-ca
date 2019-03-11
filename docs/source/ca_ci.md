# Continuous Integration Process

## Branches

- Master branch contains the latest changes. All development Gerrit patchsets usually need to be sent to master.

## Continuous Integration

- In master & release-1.4 branches we use Jenkins pipeline as a code approach.
- Every Gerrit patchset triggers a verify job and run the below tests from `Jenkinsfile`
    - static code validation (make checks)
    - Documentation build (tox -edocs)
    - Unit tests (make unit-tests)
    - FVT tests (make fvt-tests)
    - E2E tests

All the above tests run on Hyperledger infarstructure x86_64 build nodes. All these nodes uses packer with pre-configured software packages. This helps us to run tests in much faster than installing required packages everytime.

#### Static Code Validation

- We run `make checks` target to run the basic checks before kickoff the actual tests.
- It's run against every Patchset. Patchset fails if any of the checks are faile
- You can run basic checks locally:

    - make checks (Runs all check conditions (license, format, imports, lint and vet)

#### Docs Build

- We run `tox -edocs` from the root directory.
- Displays the output in the form of HTML Publisher on the `fabric-ca-verify-x86_64` job.

#### Unit Tests

- We run `make unit-test` target to run the go based unit-tests

#### FVT Tests

- We run `make fvt-tests` target to run the fvt tests. Which includes postgres, mysql related tests in it.

#### E2E tests

- We run e2e tests in the **merge job** and it performes the following tests
    - The intention of running e2e tests as part of merge job is to test the dependent tests of fabric-ca. Execute below tests
        - fabcar
        - fabric-sdk-node - We run `gulp run-end-to-end` target which executes most of the end to end tests
        - fabric-sdk-java - We run `ci_run.sh` script pre-baked in fabric-sdk-java repository.

##### Supported platforms

- x86_64 (Run the tests on verify and merge job)
- s390x (Run the tests as part of daily job)

##### Build scripts

- We use global shared library to reduce the redundant code and maintain the common code in a ci-management repository. Please see the code updated here https://github.com/hyperledger/ci-management/tree/master/vars

- Look at the `Jenkinsfile` placed in the root directory of this project.

#### CI Process Flow

As we trigger `fabric-ca-verify-x86_64` pipeline job for every gerrit patchset, we execute the tests in the below order

CleanEnvironment -- OutputEnvironment -- CloneRefSpec -- BasicChecks -- DocsBuild - Tests (Unit Test , FVT Tests) [VERIFY FLOW]

CleanEnvironment -- OutputEnvironment -- CloneRefSpec -- BasicChecks -- DocsBuild - Tests (E2E, Unit, FVT Tests) [Merge FLOW]

After the DocsBuild is passed, Jenkins Pipeline triggers Unit and FVT Tests parallel on two different nodes. After the tests are executed successfully it posts a Gerrit voting on the patchset.
If DocsBuild fails, it send the result back to Gerrit patchset and it won't trigger the further builds.

##### What happens on the merge job?

After patch got merged in the repsoitories branch, it follow the above flow and executes the e2e tests in parallel to the Unit and FVT Tests.

Jenkins clones the latest merged commit and runs the below steps

- Build fabric, fabric-ca images & Binaries
- Pull Thirdparty Images (Couchdb, zookeeper, kafka)
- Pull javaenv, nodeenv images from nexus3 (latest stable images published after successful merge job of each repo)
  - fabcar tests
  - fabric-sdk-node (npm install, gulp run-end-to-end)
  - fabric-sdk-java (Run ci_run.sh)

##### What happens if one of the build stage fails?

As we are running these tests in `fastFailure: true` (if any build stage fails in the parallel process, it will terminate/abort the current running tests and sends the result back to the Gerrit Patchset. This way, CI will avoid runnning tests when there is a failure in one of the parallel build stage.

It shows `aborted` on the aborted staged on pipeline staged view.

##### How to re-trigger failed tests?

With this pipeline flow, you can not re-trigger specific failed job, instead you can post comments `reverify` or `reverify-x` on the gerrit patchset to trigger the `fabric-ca-verify-x86_64` job which triggers pipeline flow as mentioned above.

#### Where to see the output of the stages?

Piepline supports two views (stages and blueocean). Staged views shows on the Jenkins job main page and it shows each stage in order and the status. For better view, we suggest you to access BlueOcean plugin. Click on the JOB Number and click on the **Open Blue Ocean** link that shows the build stages in pipeline view.