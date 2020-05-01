# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

import logging
import os

from . import github
from . import sns
from datetime import datetime, timedelta
from dateutil import parser, tz

logger = logging.getLogger()
logger.setLevel(logging.INFO)
# What time range to consider alerting on failures.
TIME_WINDOW_BEGIN = datetime.now().astimezone(tz.UTC) - timedelta(hours=float(os.getenv('MONITOR_FREQ_IN_HOURS')))
TIME_WINDOW_END = datetime.now().astimezone(tz.UTC)


class GitHubActions(github.GitHubClient):
    params = {
        # Needed when using an API key
        'github_username': os.getenv('github_username', None),
        'github_password': os.getenv('github_password', None),
        # Use from within an Action - ignored if username set
        'token': os.getenv('GITHUB_TOKEN', None),
        'repo_organization': os.getenv('GITHUB_REPO_ORG'),
        'repo': os.getenv('GITHUB_REPO')
    }


class S2nNotices(sns.SNSClient):
    params = {
        'topic_arn': 'arn:aws:sns:us-west-2:024603541914:s2n_notices'
    }


def message_text():
    """ Formatting for text message. """
    return """
s2n GitHub Action monitor notice
State: {conclusion}
Repo: {repo}
GHA failure time: {time}
Workflow name: {workflow_name}
URL: {url}
started by: {commit_owner}\n
"""


def main():
    """ Main entrypoint. """
    logging.info('Starting up')
    plaintext_notice = []
    gh_api = GitHubActions()
    s2n_text_client = S2nNotices()

    # Get the Action workflow log from the Github API
    gh_api.get_workflow_log_chunk(final_state='failure')
    logging.info(f"Looking for failures newer than {TIME_WINDOW_BEGIN} in {gh_api.params['repo_organization']}"
                 f"/{gh_api.params['repo']}")
    if gh_api.worklog:
        for enhanced_worklog in gh_api.worklog:
            # Parse the event date/time so we can compare it
            datetime_creation = parser.parse(enhanced_worklog['created_at'])
            logging.debug(f"looking at event from {enhanced_worklog['created_at']}")

            # If the event is recent enough, process it.
            if datetime_creation > TIME_WINDOW_BEGIN:
                logging.debug(f"Workflow_url: {enhanced_worklog['workflow_url']}")
                # The name of the workflow isn't in the failure object, look it up.
                enhanced_worklog['workflow_name'] = gh_api.get_workflow_name(enhanced_worklog['workflow_url'].split('/')[-1:][0])
                enhanced_worklog['repo'] = gh_api.params['repo']

                # Construct a notification string.
                notice_msg = message_text().format(
                    conclusion=enhanced_worklog['conclusion'],
                    time=enhanced_worklog['created_at'],
                    url=enhanced_worklog['html_url'],
                    commit_owner=enhanced_worklog['head_commit']['author']['email'],
                    repo=enhanced_worklog['repo'],
                    workflow_name=enhanced_worklog['workflow_name'])
                logging.debug(notice_msg)
                plaintext_notice.append(notice_msg)
            else:
                logging.debug("event outside time range.")
    else:
        logging.info("GH API returned empty worklog")


    # Relay messages to SNS
    if plaintext_notice:
        # Combine multiple message together.
        logging.info(s2n_text_client.publish("\n".join(plaintext_notice)))
        logging.info(f"Notices published")
    logging.info("Done")


if __name__ == '__main__':
    main()
