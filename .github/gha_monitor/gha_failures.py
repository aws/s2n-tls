#!/usr/bin/env python3

import logging
import os

from modules import github
from modules import sns
from datetime import datetime, timedelta
from dateutil import parser, tz

logger = logging.getLogger()
logger.setLevel(logging.INFO)
# What time range to consider alerting on failures.
TIME_WINDOW_BEGIN = datetime.now().astimezone(tz.UTC) - timedelta(hours=float(os.getenv('MONITOR_FREQ_IN_HOURS')))
TIME_WINDOW_END = datetime.now().astimezone(tz.UTC)


class GitHub_Actions(github.GitHub_Client):
    params = {
        # Needed when using an API key
        'github_username': os.getenv('github_username'),
        'github_password': os.getenv('github_password'),
        # Use from within an Action - ignored if username set
        'token': os.getenv('GITHUB_TOKEN'),
        'repo_organization': os.getenv('GITHUB_REPO_ORG'),
        'repo': os.getenv('GITHUB_REPO')
    }


class S2n_Notices(sns.SNS_Client):
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
    assert TIME_WINDOW_BEGIN < datetime.now().astimezone(tz.UTC)
    logging.info('Starting up')
    plaintext_notice = []
    gh_api = GitHub_Actions()
    s2n_text_client = S2n_Notices()

    # Get the Action workflow log from the Github API
    gh_api.get_workflow_log_chunk(final_state='failure')
    logging.info(f"Looking for failures newer than {TIME_WINDOW_BEGIN} in {gh_api.params['repo_organization']}"
                 f"/{gh_api.params['repo']}")
    if gh_api.worklog:
        for i in gh_api.worklog:
            # We're going to lookup some of the API URLs
            enhanced_worklog = i

            # Parse the event date/time so we can compare it
            datetime_creation = parser.parse(i['created_at'])
            logging.debug(f"looking at event from {enhanced_worklog['created_at']}")

            # If the event is recent enough, process it.
            if datetime_creation > TIME_WINDOW_BEGIN:
                logging.debug("Workflow_url: " + enhanced_worklog['workflow_url'])
                # The name of the workflow isn't in the failure object, look it up.
                enhanced_worklog['workflow_name'] = gh_api.get_workflow_name(i['workflow_url'].split('/')[-1:][0])
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
        for msg in plaintext_notice:
            logging.info(s2n_text_client.publish(msg))
            logging.info(f"Notices published")
    logging.info("Done")


if __name__ == '__main__':
    main()
