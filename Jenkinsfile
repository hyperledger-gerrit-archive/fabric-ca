#!groovy

// Copyright IBM Corp All Rights Reserved
//
// SPDX-License-Identifier: Apache-2.0
//

// Jenkinfile will get triggered on verify and merge jobs and run basicChecks, docsBuild as a pre-tests
// and call unitTests, fvtTests to run on parallel build nodes.
// along with above mentioned tests, merge job also triggers e2e tests (fabcar, e2e_sdk_node & e2e_sdk_java)

@Library("fabric-ci-lib") _
// global shared library from ci-management repository
// https://github.com/hyperledger/ci-management/tree/master/vars (Global Shared scripts)
timestamps { // set the timestamps on the jenkins console
  timeout(60) { // Build timeout set to 60 mins
    node ('hyp-x') { // trigger jobs on x86_64 builds nodes
      def DOC_CHANGE
      def CODE_CHANGE
      def failure_stage = "none"
      env.MARCH = sh(returnStdout: true, script: "uname -m | sed 's/x86_64/amd64/g'").trim()
      buildStages() // call buildStages
    } // end node block
  } // end timeout block
} // end timestamps block

def buildStages() {
  try {
    def nodeHome = tool 'nodejs-8.14.0'
    def ROOTDIR = pwd()
    stage('Clean Environment') {
      sh 'docker images | grep "dev-*|none*|test-vp*|peer[0-9]-" | awk '{print \$3}' | xargs docker rmi -f 2>/dev/null'
      // delete working directory
      deleteDir()
      // Clean build environment before start the build
      fabBuildLibrary.cleanupEnv()
      // Display jenkins environment details
      fabBuildLibrary.envOutput()
    }

    stage('Checkout SCM') {
      // Clone changes from gerrit
      fabBuildLibrary.cloneRepo('fabric-ca')
      dir("$ROOTDIR/$BASE_DIR") {
        DOC_CHANGE = sh(returnStdout: true, script: "git diff-tree --no-commit-id --name-only -r HEAD | egrep '.md\$|.rst\$|.txt\$|conf.py\$|.png\$|.pptx\$|.css\$|.html\$|.ini\$' | wc -l").trim()
        println DOC_CHANGE
        CODE_CHANGE = sh(returnStdout: true, script: "git diff-tree --no-commit-id --name-only -r HEAD | egrep -v '.md\$|.rst\$|.txt\$|conf.py\$|.png\$|.pptx\$|.css\$|.html\$|.ini\$' | wc -l").trim()
        println CODE_CHANGE
      }
      // Load properties from ci.properties file
      props = fabBuildLibrary.loadProperties()
      // Set PATH
      env.GOROOT = "/opt/go/go" + props["GO_VER"] + ".linux." + "$MARCH"
      env.GOPATH = "$WORKSPACE/gopath"
      env.PATH = "$GOROOT/bin:$GOPATH/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:${nodeHome}/bin:$PATH"
    }

      if (DOC_CHANGE > 0 && CODE_CHANGE == 0) {
        println "ONLY DOC BUILD"
        docsBuild()
      } else if (DOC_CHANGE > 0 && CODE_CHANGE > 0) {
          println "CODE AND DOC BUILD"
          basicChecks()
          docsBuild()
          runTests()
      } else {
          println "CODE BUILD"
          basicChecks() // basic checks
          println "CODE TESTS"
          runTests() // e2e on merge and unit, fvt tests on parallel
      }
    } finally { // post build actions
        // Don't fail the build if coverage report is not generated
        step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false,
          coberturaReportFile: '**/coverage.xml', failUnhealthy: false, failUnstable: false,
          failNoReports: false, maxNumberOfBuilds: 0, sourceEncoding: 'ASCII', zoomCoverageChart: false])
        // Don't fail the build if doc output is missing
        publishHTML([allowMissing: true,
          alwaysLinkToLastBuild: true,
          keepAll: true,
          reportDir: 'html',
          reportFiles: 'index.html',
          reportName: 'Docs Output'
        ])
        // Don't fail the build if there is no log file
        archiveArtifacts allowEmptyArchive: true, artifacts: '**/*.log'
        // Send notifications only for merge failures
        if (env.JOB_TYPE == "merge") {
          if (currentBuild.result == 'FAILURE') {
            // Send notification to rocketChat channel
            // Send merge build failure email notifications to the submitter
            sendNotifications(currentBuild.result, props["CHANNEL_NAME"])
          }
        }
      } // end finally block
} // end build stages

def docsBuild () {
  def ROOTDIR = pwd()
  stage("Docs Build") {
	  wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
        dir("$ROOTDIR/$BASE_DIR") {
				  sh ''' set +x -ue
            echo "-------> tox VERSION"
            tox --version
            pip freeze
            tox -edocs
            cp -r docs/_build/html/ $WORKSPACE
          '''
        }
      } catch (err) {
          failure_stage = "Docs Build"
          currentBuild.result = 'FAILURE'
          throw err
			}
    }
  }
}

def basicChecks() {
  def ROOTDIR = pwd()
  stage("Basic Checks") {
    wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
      try {
        dir("$ROOTDIR/$BASE_DIR") {
          // runs all check conditions (license, format, imports, lint and vet)
          sh 'make checks'
        }
      } catch (err) {
          failure_stage = "basicChecks"
          currentBuild.result = 'FAILURE'
          throw err
      }
    }
  }
}

def fabCar() {
  def ROOTDIR = pwd()
  stage("Fab Car Tests") {
    wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
      try {
        // Clone fabric-samples repository
        fabBuildLibrary.cloneScm('fabric-samples', '$GERRIT_BRANCH')
        sh 'echo npm version \$(npm -v)'
        sh 'echo node version \$(node -v)'
        println "Delete all containers"
        sh 'docker rm -f $(docker ps -aq) 2>/dev/null'
        println "Delete unused docker images"
        sh 'docker images | grep "dev-*|none*|test-vp*|peer[0-9]-" | awk '{print \$3}' | xargs docker rmi -f 2>/dev/null'
        sh 'docker ps -a && docker images'
        dir("$ROOTDIR/gopath/src/github.com/hyperledger/fabric-samples/scripts/Jenkins_Scripts") {
          sh './fabcar.sh'
        }
        stash name: "buildLogs", includes: "**/*.log"
      } catch (err) {
          failure_stage = "fabCar"
          currentBuild.result = 'FAILURE'
          throw err
      }
    }
  }
}

def e2e_sdk_node() {
  def ROOTDIR = pwd()
  stage("e2e_sdk_node") {
    wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
      try {
        // Clone fabric-sdk-node repository
        fabBuildLibrary.cloneScm('fabric-sdk-node', '$GERRIT_BRANCH')
        sh 'echo npm version \$(npm -v)'
        sh 'echo node version \$(node -v)'
        println "Delete all containers"
        sh 'docker rm -f $(docker ps -aq) 2>/dev/null'
        println "Delete unused docker images"
        sh 'docker images | grep "dev-*|none*|test-vp*|peer[0-9]-" | awk '{print \$3}' | xargs docker rmi -f 2>/dev/null'
        sh 'docker ps -a && docker images'
        dir("$ROOTDIR/gopath/src/github.com/hyperledger/fabric-sdk-node") {
          sh '''set +x -ue
            npm install
            npm install -g gulp && npm install -g istanbul
            gulp
            gulp ca
            echo " ==== generate certificates using cryptogen ==== "
            gulp install-and-generate-certs
            echo " ==== Run gulp tests ==== "
            gulp test
          '''
        }
      } catch (err) {
          failure_stage = "e2e_sdk_node"
          currentBuild.result = 'FAILURE'
          throw err
			}
    }
  }
}

def e2e_sdk_java() {
  def ROOTDIR = pwd()
  stage("e2e_sdk_java") {
    wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
      try {
        // Clone fabric-sdk-java repository
        fabBuildLibrary.cloneScm('fabric-sdk-java', '$GERRIT_BRANCH')
        println "Delete all containers"
        sh 'docker rm -f $(docker ps -aq) 2>/dev/null'
        println "Delete unused docker images"
        sh 'docker images | grep "dev-*|none*|test-vp*|peer[0-9]-" | awk '{print \$3}' | xargs docker rmi -f 2>/dev/null'
        sh 'docker ps -a && docker images'
        dir("$ROOTDIR/gopath/src/github.com/hyperledger/fabric-sdk-java") {
          sh '''set +x -ue
            export WD=$WORKSPACE/gopath/src/github.com/hyperledger/fabric-sdk-java
            export GOPATH=$WD/src/test/fixture
            cd $WD/src/test
            chmod +x cirun.sh
            ./cirun.sh
          '''
        }
      } catch (err) {
          failure_stage = "e2e_sdk_java"
          currentBuild.result = 'FAILURE'
          throw err
			}
    }
  }
}

def runTests() {
  def ROOTDIR = pwd()
  stage ("Tests") {
    parallel (
      "e2e-Tests" : {
         // Run e2e tests only on Merge job
          if (env.JOB_TYPE == "merge") {
            stage("e2e-Tests") {
              wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
                try {
                  // Build fabri-ca docker images and binaries
                  fabBuildLibrary.fabBuildImages('fabric-ca', 'dist docker')
                  // Clone fabric repository
                  fabBuildLibrary.cloneScm('fabric', '$GERRIT_BRANCH')
                  // Build fabric images and binaries
                  fabBuildLibrary.fabBuildImages('fabric', 'dist docker')
                  // Pull thirdparty images from DockerHub
                  fabBuildLibrary.pullThirdPartyImages(props["FAB_BASEIMAGE_VERSION"], props["FAB_THIRDPARTY_IMAGES_LIST"])
                  // Pull latest stable images from nexus3
                  fabBuildLibrary.pullDockerImages(props["FAB_BASE_VERSION"], props["FAB_IMAGES_LIST"])
                  // Test fabcar on fabric-samples
                  fabCar()
                  // Test e2e tests on sdk-node
                  e2e_sdk_node()
                  // Test e2e tests on sdk-java
                  e2e_sdk_java()

                } catch (err) {
                    failure_stage = "e2e-Tests"
                    currentBuild.result = 'FAILURE'
                    throw err
			          }
              }
            }
          }
      },

      "Unit Tests" : {
        node('hyp-x') {
          stage("UnitTests") {
            wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
              try {
                // Clone repository
                fabBuildLibrary.cloneRepo('fabric-ca')
                dir("$ROOTDIR/$BASE_DIR") {
                  // Performs checks first and runs the go-test based unit tests
                  sh 'make unit-test int-tests docs'
                  // Stash the coverage report
                  stash name: "coverageReport", includes: "**/coverage.xml"
                }
              }
              catch (err) {
                failure_stage = "UnitTests"
                currentBuild.result = 'FAILURE'
                throw err
              }
            }
          }
        }
      },
      "FVT Tests" : {
        node('hyp-x') {
          stage("FVT Tests") {
            wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
              try {
                // Clone repository
                fabBuildLibrary.cloneRepo('fabric-ca')
                dir("$ROOTDIR/$BASE_DIR") {
                  // Run FVT Tests
                  sh 'make fvt-tests'
                }
              } catch (err) {
                failure_stage = "FVT Tests"
                currentBuild.result = 'FAILURE'
                throw err
			        }
		        }
	        }
        }
      }, )

    stage("unstash") {
      if (DOC_CHANGE > 0 && CODE_CHANGE == 0) {
        // unstash not required for doc only builds
        println "Unstash not required"
      } else {
          try {
            dir("$ROOTDIR") {
              println "Unstash stashed files"
              // unstash coverageReport on main job
              unstash 'coverageReport'
              // unstash buildLogs on main job
              unstash 'buildLogs'
            }
          }
          catch (err) {
            failure_stage = "unstash"
            currentBuild.result = 'FAILURE'
            throw err
          }
        }
      }
    } // stage parallel
} // build stage