
import logging
import os
import re
from errbot import BotPlugin, botcmd
import github
import github.PaginatedList
import github.NamedUser
from github.GithubException import UnknownObjectException


class Githubapi(BotPlugin):
    """
    Retrieves useful information from GitHub based on conversations
    """

    issue_message = '[{repo_name}] {title} - status: {state} - owner: {assignee}, opened by: {requester}, milestone: {milestone}.'
    issue_body = 'requested by: {user} on {channel}\n\nBe sure to add a body to this issue before assigning it to anyone but yourself.'

    patterns = {}

    github_token = ''
    github_conn = None
    default_org = 'fictivekin'

    def activate(self):

        # Check for presence of github token in environment
        if not os.environ['GITHUB_TOKEN']:
            logging.info('Cannot load GitHubApi - no GITHUB_TOKEN found in the environment')
            return False

        self.github_token = os.environ['GITHUB_TOKEN']
        self.github_conn = github.Github(self.github_token)

        # Register patterns and callbacks
        self.patterns = {
            'issues': {
                'pattern': r'https?://github\.com/(\w+/\w+)/issues/(\d+)',
                'callback': self._get_issue
            },
            'pulls': {
                'pattern': r'https?://github\.com/(\w+/\w+)/pull/(\d+)',
                'callback': self._get_pull
            }
        }

        super(Githubapi, self).activate()


    def _get_issue(self, channel_id, match):
        repo_name = match.group(1)
        issue_id = int(match.group(2))
        logging.debug('Retrieving issue {} from {}'.format(issue_id, repo_name))

        try:
            repo = self.github_conn.get_repo(repo_name)
            issue = repo.get_issue(issue_id)
        except UnknownObjectException:
            return

        if issue:
            self._send_issue_data(channel_id, issue, repo)


    def _get_pull(self, channel_id, match):
        repo_name = match.group(1)
        pull_id = int(match.group(2))
        logging.debug('Retrieving PR {} from {}'.format(pull_id, repo_name))

        try:
            repo = self.github_conn.get_repo(repo_name)
            pull = repo.get_pull(pull_id)
        except UnknownObjectException:
            return

        if pull:
           self._send_issue_data(channel_id, pull, repo)


    def _send_issue_data(self, channel_id, issue_or_pull, repo):
        if not issue_or_pull.assignee:
            assignee = 'undefined'
        else:
            assignee = issue_or_pull.assignee.login

        if not issue_or_pull.milestone:
            milestone = 'undefined'
        else:
            milestone = issue_or_pull.milestone.title

        self.send(channel_id, self.issue_message.format(
                      repo_name=repo.name,
                      title=issue_or_pull.title,
                      state=issue_or_pull.state,
                      assignee=assignee,
                      requester=issue_or_pull.user.login,
                      milestone=milestone))


    def callback_message(self, msg):
        channel_id = self.build_identifier(str(msg.to));

        for pattern in self.patterns.keys():
            match = re.search(self.patterns[pattern]['pattern'], msg.body, re.IGNORECASE)
            if match is not None:
                self.patterns[pattern]['callback'](channel_id, match)


    @botcmd
    def issue(self, msg, args):
        """
           Creates an issue on behalf of a user in a specific GH repo
           Usage:
               !issue <repo> <issue title>
        """

        if len(args) < 2:
            return 'No repo or issue title specified. Usage: !issue <repo> <issue title>'

        channel_id = self.build_identifier(str(msg.to));

        repo_name = args.split(' ')[0]
        title = ' '.join(args.split(' ')[1:])

        try:
            slash_index = repo_name.index('/')
        except ValueError:
            repo_name = '{}/{}'.format(self.default_org, repo_name)

        try:
            repo = self.github_conn.get_repo(repo_name)
         
            issue = repo.create_issue(
                title, body=self.issue_body.format(
                                   user=str(msg.frm.nick),
                                   channel=str(msg.to)
                            )
            )
        except UnknownObjectException:
            return 'The specified repository does not exist: {}'.format(repo_name)

        self._send_issue_data(channel_id, issue, repo)
        return issue.html_url
