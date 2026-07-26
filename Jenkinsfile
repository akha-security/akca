pipeline {
  agent any
  options {
    timeout(time: 60, unit: 'MINUTES')
    disableConcurrentBuilds()
  }
  parameters {
    string(name: 'AKCA_TARGET', defaultValue: '', description: 'Explicitly authorized http(s) target')
    booleanParam(name: 'AKCA_AUTHORIZED', defaultValue: false, description: 'I confirm authorization to scan')
  }
  stages {
    stage('Authorized Akca DAST') {
      when {
        expression { params.AKCA_AUTHORIZED && params.AKCA_TARGET ==~ /^https?:\/\/.+/ }
      }
      steps {
        withEnv([
          "AKCA_TARGET=${params.AKCA_TARGET}",
          'AKCA_AUTHORIZED=true',
          'AKCA_REPORT_PATH=akca-results.sarif',
          'AKCA_RATE_LIMIT=10',
          'AKCA_CONCURRENCY=8'
        ]) {
          sh 'bash scripts/ci-scan.sh'
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'akca-results.sarif', allowEmptyArchive: true
    }
  }
}
