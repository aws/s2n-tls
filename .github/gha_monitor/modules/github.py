import json
import logging
from agithub import GitHub
from datetime import datetime

logger = logging.getLogger()


class GitHub_Client:
    # Over-ride
    params = {
        'github_username': None,
        'secret': None,
        'repo_organization': None,
        'repo': None
    }

    def __init__(self):
        assert self.params['repo_organization'] != None
        assert self.params['repo'] != None

        # Decide which auth method to use.
        if 'github_username' in self.params and self.params['github_username'] != None:
            assert self.params['github_password'] != None
            self._github = GitHub.GitHub(self.params['github_username'], self.params['github_password'])
            logging.debug('Using username/key to auth with Github: ' + self.params['github_username'])
        elif 'token' in self.params and self.params['token'] != None:
            logging.debug('Using a token to auth with GitHub')
            self._github = GitHub.GitHub(token=self.params['token'])

        self.response = {}
        self.worklog = None
        self.repo_org = self.params['repo_organization']
        self.repo = self.params['repo']

    def get_workflow_log_chunk(self, chunk=1, final_state='failure'):
        """
        Example using agithub:

        username= get_user
        secret = get_secret

        client = GitHub.GitHub(username, secret)
        client.repos.awslabs['private-s2n-fuzz'].actions.runs.get(page="1", status="failure")

        :param final_state: str
        :param chunk: int

        """
        (status_code, self.response) = \
            self._github.repos[self.repo_org][self.repo].actions.runs.get(page=chunk,
                                                                          status=final_state)
        if status_code < 300:
            self.worklog = GitHub_Worklog(self.response)
            return True
        else:
            return False

    def get_workflow_name(self, workflow_id):
        logging.debug(f"Looking up workflow_id {workflow_id}")
        (status_code, response) = \
            self._github.repos[self.repo_org][self.repo].actions.workflows[workflow_id].get()
        workflow_name = response['name']
        logging.debug(f"Github workflow lookup gave us {workflow_name}")
        if status_code < 300:
            return workflow_name
        else:
            return None


class GitHub_Worklog:
    def __init__(self, worklog):
        self._worklog = worklog['workflow_runs']
        self.index = len(self._worklog)

    def __iter__(self):
        return self

    def __next__(self):
        if self.index == 0:
            raise StopIteration
        self.index = self.index - 1
        return self._worklog[self.index]
