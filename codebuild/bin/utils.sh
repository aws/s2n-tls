# Utility functions
get_latest_release(){
    export LATEST_RELEASE_URL=$(gh api /repos/aws/s2n-tls/releases/latest|jq -r '.tarball_url')
    export LATEST_RELEASE_VER=$(echo $RELEASE_URL | sed 's|.*/||')
}

gh_login(){
  # Takes secrets manager key as an argument
  aws secretsmanager get-secret-value --secret-id "$1" --query 'SecretString' --output text |jq -r '.secret_key'| gh auth login --with-token
  gh auth status
}
