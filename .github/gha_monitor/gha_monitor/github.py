import logging
from agithub import GitHub

logger = logging.getLogger()


class GitHubClient:
    # Over-ride
    params = {
        'github_username': None,
        'secret': None,
        'repo_organization': None,
        'repo': None
    }

    def __init__(self):
        self._github = GitHub.GitHub(username=self.params['github_username'], password=self.params['github_password'],
                                     token=self.params['token'])
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
        return status_code

    def get_workflow_name(self, workflow_id):
        logging.debug(f"Looking up workflow_id {workflow_id}")
        (status_code, response) = \
            self._github.repos[self.repo_org][self.repo].actions.workflows[workflow_id].get()
        workflow_name = response['name']
        logging.debug(f"Github workflow lookup gave us {workflow_name}")
        return workflow_name


class GitHubWorklog:
    def __init__(self, worklog):
        self._worklog = iter(worklog['workflow_runs'])

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._worklog)
