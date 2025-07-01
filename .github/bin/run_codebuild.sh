set -ex

usage() {
    echo "run_codebuild.sh <repo> <source> <region> <project>"
    echo ""
    echo "Arguments:"
    echo "  repo        Name of the Github repository. For example: aws/s2n-tls"
    echo "  source      Source version. For example: pr/1234, 1234abcd, test_branch"
    echo "  region      AWS region of Codebuild project. For example: us-west-2"
    echo "  project     Name of the Codebuild project. For example: AddressSanitizer"
}

if [ "$#" -lt "4" ]; then
    usage
    exit 1
fi
REPO=$1
SOURCE_VERSION=$2
REGION=$3
NAME=$4

PROJECT_INFO=$(aws --region $REGION codebuild batch-get-projects --names $NAME)
if jq -e '.projects[0]' > /dev/null <<< $PROJECT_INFO; then
    echo "Found project $NAME"
else
    echo "Project $NAME not found."
    exit 1
fi

if jq -e '.projects[0].buildBatchConfig' > /dev/null <<< $PROJECT_INFO; then
    echo "Project is batch build"
    START_COMMAND="start-build-batch"
    GET_COMMAND="batch-get-build-batches"
    BUILD_ID_FIELD=".buildBatch.id"
    STATUS_FIELD=".buildBatches[0].buildBatchStatus"
else
    echo "Project is NOT batch build"
    START_COMMAND="start-build"
    GET_COMMAND="batch-get-builds"
    BUILD_ID_FIELD=".build.id"
    STATUS_FIELD=".builds[0].buildStatus"
fi

BUILD_ID=$(aws --region $REGION codebuild $START_COMMAND --project-name $NAME --source-location-override https://github.com/$REPO --source-version $SOURCE_VERSION | jq -re "$BUILD_ID_FIELD")
echo "Launched build: $BUILD_ID"

STATUS="IN_PROGRESS"
until [ "$STATUS" != "IN_PROGRESS" ]; do
    sleep 600
    STATUS=$(aws --region $REGION codebuild $GET_COMMAND --id $BUILD_ID | jq -re "$STATUS_FIELD")
    echo "Status: $STATUS"
done

if [ "$STATUS" = "SUCCEEDED" ]; then
    exit 0
else
    exit 1
fi
