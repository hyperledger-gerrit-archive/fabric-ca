// Copyright IBM Corp All Rights Reserved
//
// SPDX-License-Identifier: Apache-2.0
//
timeout(60) {
node ('hyp-x') { // trigger build on x86_64 node
 timestamps {
    try {
     def ROOTDIR = pwd() // workspace dir (/w/workspace/<job_name>
     env.ROOTDIR = pwd()
     def nodeHome = tool 'nodejs-8.11.3'
     env.PROJECT_DIR = "gopath/src/github.com/hyperledger"
     env.JAVA_HOME = "/usr/lib/jvm/java-1.8.0-openjdk-amd64"
     env.GO_VER = sh(returnStdout: true, script: 'curl -O https://raw.githubusercontent.com/hyperledger/fabric-ca/master/ci.properties && cat ci.properties | grep "GO_VER" | cut -d "=" -f2').trim()
     env.ARCH = "amd64"
     env.GOROOT = "/opt/go/go${GO_VER}.linux.${ARCH}"
     env.GOPATH = "$WORKSPACE/gopath"
     env.PATH = "$GOROOT/bin:$GOPATH/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:${nodeHome}/bin:$PATH"
     def failure_stage = "none"
	// delete working directory
	deleteDir()
	stage("Fetch Patchset") { // fetch gerrit refspec on latest commit
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
            if (REFSPEC != null)  {
                   println "$GERRIT_REFSPEC"
                   println "$GERRIT_BRANCH"
                   checkout([
                       $class: 'GitSCM',
                       branches: [[name: '$GERRIT_REFSPEC']],
                       extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'gopath/src/github.com/hyperledger/$PROJECT'], [$class: 'CheckoutOption', timeout: 10]],
                       userRemoteConfigs: [[credentialsId: 'hyperledger-jobbuilder', name: 'origin', refspec: '$GERRIT_REFSPEC:$GERRIT_REFSPEC', url: '$GIT_BASE']]])
            } else {
                   // Clone fabric-ca on merge
                   println "Clone $PROJECT repository"
                   checkout([
                       $class: 'GitSCM',
                       branches: [[name: 'refs/heads/$GERRIT_BRANCH']],
                       extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'gopath/src/github.com/hyperledger/$PROJECT']],
                       userRemoteConfigs: [[credentialsId: 'hyperledger-jobbuilder', name: 'origin', refspec: '+refs/heads/$GERRIT_BRANCH:refs/remotes/origin/$GERRIT_BRANCH', url: '$GIT_BASE']]])
              }
              dir("${ROOTDIR}/$PROJECT_DIR/$PROJECT") {
              sh '''
                 # Print last two commit details
                 echo
                 git log -n2 --pretty=oneline --abbrev-commit
                 echo
              '''
              }
           }
            catch (err) {
                failure_stage = "Fetch patchset"
                currentBuild.result = 'FAILURE'
                throw err
			}
		}
	}

     // clean environment and get env data
	stage("Clean Environment - Get Env Info") {
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
				dir("${ROOTDIR}/$PROJECT_DIR/fabric-ca/scripts/Jenkins_Scripts") {
			    sh './CI_Script.sh --clean_Environment --env_Info'
			}
		}
			catch (err) {
			    failure_stage = "Clean Environment - Get Env Info"
			    currentBuild.result = 'FAILURE'
                throw err
			}
		}
	}

if (env.JOB_NAME == "fabric-ca-end-2-end-merge-x86_64" || env.JOB_NAME == "fabric-ca-end-2-end-verify-x86_64") {
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
		    // Clone fabric and Build Docker Images
			fabricBuild()
			// Clone fabric-ca and Build Docker Images
			fabricCABuild()
			// Run SDK NODE IntegrationTests
			sdkNodeBuild()
			// Run Java SDK IntegrationsTests
			// Java Builds are disabled till IN-39 is fixed
			// sdkJavaBuild()
		}
}

// Verify Docs Build
if (env.JOB_NAME == "fabric-ca-docs-verify") {
    docsBuild()
    docsOutPut()
}

// Trigger only on Unit-tests jobs
if (env.JOB_NAME == "fabric-ca-unit-tests-verify-x86_64" || env.JOB_NAME == "fabric-ca-unit-tests-merge-x86_64") {
    unitTests()
}
   } finally {
		if (env.JOB_NAME == "fabric-ca-end-2-end-merge-x86_64" || env.JOB_NAME == "fabric-ca-unit-tests-merge-x86_64") {
			if (currentBuild.result == 'FAILURE') { // Other values: SUCCESS, UNSTABLE
				rocketSend message: "Build Notification - STATUS: *${currentBuild.result}* - BRANCH: *${env.GERRIT_BRANCH}* - PROJECT: *${env.PROJECT}* - BUILD_URL:  (<${env.BUILD_URL}|Open>)"
			}
		}
	} // finally block end here
  } // timestamps end here
} // node block end here
} // timeout block end here

def unitTests() {
// unit-tests
	stage("UnitTests") {
	def ROOTDIR = pwd()
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
				dir("${ROOTDIR}/$PROJECT_DIR/fabric-ca") {
					// Run Unit-Tests
					sh 'make ci-tests'
					// Generate Coverage Report
					step([$class: 'CoberturaPublisher', autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: '**/coverage.xml', failUnhealthy: false, failUnstable: false, failNoReports: false, maxNumberOfBuilds: 0, onlyStable: false, sourceEncoding: 'ASCII', zoomCoverageChart: false])
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

def docsBuild() {
// Run CA Docs Tests
	stage("Doc Build") {
	def ROOTDIR = pwd()
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
				dir("${ROOTDIR}/$PROJECT_DIR/fabric-ca") {
					sh '''
						echo "-------> tox VERSION"
						tox --version
						pip freeze
						cd "$GOPATH/src/github.com/hyperledger/fabric-ca" || exit
						tox -edocs
					'''
				}
			}
		    catch (err) {
			    failure_stage = "doc_build"
				currentBuild.result = 'FAILURE'
				throw err
			}
		}
	}
}
// CA Docs HTML Report
def docsOutPut() {
	stage("Doc Output") {
	def ROOTDIR = pwd()
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			dir("${ROOTDIR}/$PROJECT_DIR") {
				publishHTML([allowMissing: false,
				alwaysLinkToLastBuild: true,
				keepAll: true,
				reportDir:
				'fabric-ca/docs/_build/html',
				reportFiles: 'index.html',
				reportName: 'Docs Output'
				])
			}
		}
	}
}

def fabricBuild() {
// Pull fabric
	stage("Build fabric Docker Images") {
	def ROOTDIR = pwd()
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
				dir("${ROOTDIR}/$PROJECT_DIR") {
				sh '''
					# Clone fabric repository
					git clone --single-branch -b $GERRIT_BRANCH --depth 2 git://cloud.hyperledger.org/mirror/fabric
					echo -e "\033[32m cloned fabric repository" "\033[0m"
					cd fabric
					# Print last two commits
					echo
					git log -n2 --pretty=oneline --abbrev-commit
					echo
					# Build fabric Docker Images
					make docker
				'''
				}
			}
			catch (err) {
				failure_stage = "build fabric"
				currentBuild.result = 'FAILURE'
				throw err
			}
		}
	}
}

def fabricCABuild() {
// Pull fabric-ca
	stage("Build fabric-ca Docker Images") {
	def ROOTDIR = pwd()
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
				dir("${ROOTDIR}/$PROJECT_DIR/fabric-ca") {
				sh '''
					# Build fabric-ca Docker Images
					make docker-fabric-ca
				'''
				}
			}
			catch (err) {
				failure_stage = "build fabric-ca"
				currentBuild.result = 'FAILURE'
				throw err
			}
		}
	}
}

def sdkNodeBuild() {
// Run gulp tests (IntegrationTests)
	stage("SDK NODE E2E Tests") {
	def ROOTDIR = pwd()
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
				dir("${ROOTDIR}/$PROJECT_DIR/fabric-ca/scripts/Jenkins_Scripts") {
					sh './CI_Script.sh --pullJavaEnv --node_E2e_Tests'
				}
			}
			catch (err) {
				failure_stage = "node_E2e_Tests"
				currentBuild.result = 'FAILURE'
				throw err
			}
		}
	}
}

def sdkJavaBuild() {
// Run JAVA SDK IntegrationTests
	if (env.GERRIT_BRANCH == "release-1.0") {
		echo "======> Don't run JAVA SDK E2E Tests on $GERRIT_BRANCH"
		exit 0
	}
	stage("SDK Java E2E Tests") {
	def ROOTDIR = pwd()
		wrap([$class: 'AnsiColorBuildWrapper', 'colorMapName': 'xterm']) {
			try {
				dir("${ROOTDIR}/$PROJECT_DIR") {
				sh '''
					# Clone fabric-sdk-java repository
					git clone --single-branch -b $GERRIT_BRANCH git://cloud.hyperledger.org/mirror/fabric-sdk-java
					echo -e "\033[32m cloned fabric-sdk-java repository" "\033[0m"
					export GOPATH=${ROOTDIR}/$PROJECT_DIR/fabric-sdk-java/src/test/fixture
					cd fabric-sdk-java/src/test
					# Print last two commits
					echo
					git log -n2 --pretty=oneline --abbrev-commit
					echo
					chmod +x cirun.sh
					WD=${ROOTDIR}/$PROJECT_DIR/fabric-sdk-java ./cirun.sh
				'''
				}
			}
			catch (err) {
                failure_stage = "java_sdk_e2e"
			    currentBuild.result = 'FAILURE'
			    throw err
			}
		}
	}
}
