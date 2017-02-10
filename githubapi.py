
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
    issue_comment = 'commented by: {user} on {channel}\n\n{comment}.'

    patterns = {}

    github_token = ''
    github_conn = None
    default_org = 'fictivekin'

    _org_members = []

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
                'pattern': r'https?://github\.com/([\w-]+/[\w-]+)/issues/(\d+)',
                'callback': self._show_issue
            },
            'pulls': {
                'pattern': r'https?://github\.com/([\w-]+/[\w-]+)/pull/(\d+)',
                'callback': self._show_pull
            }
        }

        super(Githubapi, self).activate()


    def _lookup_user_in_org(self, username):
        org = self._get_org(self.default_org)
        if not org:
            return False

        if not self._org_members:
            try:
                self._org_members = org.get_members()
            except UnknownObjectException:
                return False

        for member in self._org_members:
            if username == member.username:
                return member

        return False


    def _get_org(self, org_name):
        try:
            org = self.github_conn.get_organization(org_name)
        except UnknownObjectException:
            return False

        return org


    def _get_repo(self, repo_name):
        try:
            # Repo name already has a '/', so it's a fully-qualified repo name
            slash_index = repo_name.index('/')
        except ValueError:
            # Add the default org to the repo, since it was the short name
            repo_name = '{}/{}'.format(self.default_org, repo_name)

        try:
            repo = self.github_conn.get_repo(repo_name)
        except UnknownObjectException:
            return False

        return repo


    def _get_issue(self, repo_name, issue_id):
        return self._get_issue_or_pull(repo_name, issue_id, False)


    def _get_pull(self, repo_name, pull_id):
        return self._get_issue_or_pull(repo_name, pull_id, True)


    def _get_issue_or_pull(self, repo_name, issue_or_pull_id, is_pull):
        repo = self._get_repo(repo_name)
        if not repo:
            return False

        try:
            if is_pull:
                issue_or_pull = repo.get_pull(issue_or_pull_id)
            else:
                issue_or_pull = repo.get_issue(issue_or_pull_id)
        except UnknownObjectException:
            return False

        return issue_or_pull


    def _show_issue(self, channel_id, match):
        repo_name = match.group(1)
        issue_id = int(match.group(2))
        logging.debug('Retrieving issue {} from {}'.format(issue_id, repo_name))

        issue = self._get_issue(repo_name, issue_id)
        if issue:
            self._send_issue_data(channel_id, issue, repo_name)


    def _show_pull(self, channel_id, match):
        repo_name = match.group(1)
        pull_id = int(match.group(2))
        logging.debug('Retrieving PR {} from {}'.format(pull_id, repo_name))

        pull = self._get_pull(repo_name, pull_id)
        if pull:
            self._send_issue_data(channel_id, pull, repo_name)


    def _send_issue_data(self, channel_id, issue_or_pull, repo_name):
        if not issue_or_pull.assignee:
            assignee = 'undefined'
        else:
            assignee = issue_or_pull.assignee.login

        if not issue_or_pull.milestone:
            milestone = 'undefined'
        else:
            milestone = issue_or_pull.milestone.title

        self.send(channel_id, self.issue_message.format(
                      repo_name=repo_name,
                      title=issue_or_pull.title,
                      state=issue_or_pull.state,
                      assignee=assignee,
                      requester=issue_or_pull.user.login,
                      milestone=milestone))


    def callback_message(self, msg):
        author_nick = str(msg.frm.nick)
        ignore_nicks = [self.bot_identifier.nick, 'github']

        # Ignore all messages from the bot itself
        if author_nick in ignore_nicks:
            return

        if str(msg.to) == self.bot_identifier.nick:
            channel_id = self.build_identifier(str(msg.frm.nick))
        else:
            channel_id = self.build_identifier(str(msg.to));

        for pattern in self.patterns.keys():
            match = re.search(self.patterns[pattern]['pattern'], msg.body, re.IGNORECASE)
            if match is not None:
                self.patterns[pattern]['callback'](channel_id, match)


    @botcmd(split_args_with=' ')
    def assign(self, msg, args):
        """
            Assigns an issue to a specific GitHub handle
            Usage:
                !assign <repo> <issue_id> <user>
        """

        if len(args) < 3:
            return 'No repo or issue id specified. Usage: !assign <repo> <issue_id> <user>'

        if str(msg.to) == self.bot_identifier.nick:
            channel_id = self.build_identifier(str(msg.frm.nick))
        else:
            channel_id = self.build_identifier(str(msg.to));

        issue = _get_issue(args[0], args[1])
        if not issue:
            return 'Either the specified repository does not exist or the issue id is invalid'

        assignees = []
        for assignee in args[2:]:
            user = self._lookup_user_in_org(assignee)
            if user:
                assignees.append(user)

        if not assignees:
            return 'No valid assignees were found'

        try:
            issue.add_to_assignees(
                *assignees
            )
        except UnknownObjectException:
            return 'An error occurred assigning that user'

        return 'Assigned: {}'.assignee


    @botcmd(split_args_with=' ')
    def comment(self, msg, args):
        """
           Comments on an issue on behalf of a user in a specific GH repo
           Usage:
               !comment <repo> <issue_id> <comment>
        """

        if len(args) < 3:
            return 'No repo or issue id specified. Usage: !comment <repo> <issue_id> <comment>'

        if str(msg.to) == self.bot_identifier.nick:
            channel_id = self.build_identifier(str(msg.frm.nick))
        else:
            channel_id = self.build_identifier(str(msg.to));

        issue = self._get_issue(args[0], args[1])
        if not issue:
            return 'Either the specified repository does not exist or the issue id is invalid'

        comment = ' '.join(args[2:])
        try:
            comment = issue.create_comment(
                self.issue_comment.format(
                                   user=str(msg.frm.nick),
                                   channel=str(msg.to),
                                   comment
                            )
            )
        except UnknownObjectException:
            return 'An error occurred saving the comment'

        return comment.html_url


    @botcmd(split_args_with=' ')
    def issue(self, msg, args):
        """
           Creates an issue on behalf of a user in a specific GH repo
           Usage:
               !issue <repo> <issue title>
        """

        if len(args) < 2:
            return 'No repo or issue title specified. Usage: !issue <repo> <issue title>'

        if str(msg.to) == self.bot_identifier.nick:
            channel_id = self.build_identifier(str(msg.frm.nick))
        else:
            channel_id = self.build_identifier(str(msg.to));

        repo = self._get_repo(args[0])
        if not repo:
            return 'The specified repository does not exist: {}'.format(repo_name)

        title = ' '.join(args[1:])

        try:
            issue = repo.create_issue(
                title, body=self.issue_body.format(
                                   user=str(msg.frm.nick),
                                   channel=str(msg.to)
                            )
            )
        except UnknownObjectException:
            return 'The specified repository does not exist: {}'.format(repo_name)

        return issue.html_url
