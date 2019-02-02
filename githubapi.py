import logging
import os
import re
from errbot import BotPlugin, botcmd, webhook
import github
import github.PaginatedList
import github.NamedUser
from github.GithubException import UnknownObjectException


class Githubapi(BotPlugin):
    """
    Retrieves useful information from GitHub based on conversations
    """

    issue_message = "[{repo_name}] {title} - status: {state} - owner: {assignee}, opened by: {requester}, milestone: {milestone}."
    issue_body = "requested by: {user} on {channel}\n\nBe sure to add a body to this issue before assigning it to anyone but yourself."

    patterns = {}

    github_token = ""
    github_conn = None
    default_org = os.environ.get("GITHUB_ORG", "fictivekin")

    def activate(self):

        # Check for presence of github token in environment
        self.github_token = os.environ.get("GITHUB_TOKEN")
        if not self.github_token:
            logging.info(
                "Cannot load GitHubApi - no GITHUB_TOKEN found in the environment"
            )
            return False

        self.github_conn = github.Github(self.github_token)

        # Register patterns and callbacks
        self.patterns = {
            "issues": {
                "pattern": r"https?://github\.com/([\w-]+/[\w-]+)/issues/(\d+)",
                "callback": self._get_issue,
            },
            "pulls": {
                "pattern": r"https?://github\.com/([\w-]+/[\w-]+)/pull/(\d+)",
                "callback": self._get_pull,
            },
        }

        super(Githubapi, self).activate()

    def _get_issue(self, channel_id, match):
        repo_name = match.group(1)
        issue_id = int(match.group(2))
        logging.debug("Retrieving issue {} from {}".format(issue_id, repo_name))

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
        logging.debug("Retrieving PR {} from {}".format(pull_id, repo_name))

        try:
            repo = self.github_conn.get_repo(repo_name)
            pull = repo.get_pull(pull_id)
        except UnknownObjectException:
            return

        if pull:
            self._send_issue_data(channel_id, pull, repo)

    def _send_issue_data(self, channel_id, issue_or_pull, repo):
        if not issue_or_pull.assignee:
            assignee = "undefined"
        else:
            assignee = issue_or_pull.assignee.login

        if not issue_or_pull.milestone:
            milestone = "undefined"
        else:
            milestone = issue_or_pull.milestone.title

        self.send(
            channel_id,
            self.issue_message.format(
                repo_name=repo.name,
                title=issue_or_pull.title,
                state=issue_or_pull.state,
                assignee=assignee,
                requester=issue_or_pull.user.login,
                milestone=milestone,
            ),
        )

    def callback_message(self, msg):
        author_nick = str(msg.frm.nick)
        ignore_nicks = [self.bot_identifier.nick, "github"]

        # Ignore all messages from the bot itself
        if author_nick in ignore_nicks:
            return

        if str(msg.to) == self.bot_identifier.nick:
            channel_id = self.build_identifier(str(msg.frm.nick))
        else:
            channel_id = self.build_identifier(str(msg.to))

        for pattern in self.patterns.keys():
            match = re.search(
                self.patterns[pattern]["pattern"], msg.body, re.IGNORECASE
            )
            if match is not None:
                self.patterns[pattern]["callback"](channel_id, match)

    @botcmd
    def issue(self, msg, args):
        """
           Creates an issue on behalf of a user in a specific GH repo
           Usage:
               !issue <repo> <issue title>
        """

        if len(args) < 2:
            return (
                "No repo or issue title specified. Usage: !issue <repo> <issue title>"
            )

        if str(msg.to) == self.bot_identifier.nick:
            channel_id = self.build_identifier(str(msg.frm.nick))
        else:
            channel_id = self.build_identifier(str(msg.to))

        repo_name = args.split(" ")[0]
        title = " ".join(args.split(" ")[1:])

        try:
            slash_index = repo_name.index("/")
        except ValueError:
            repo_name = "{}/{}".format(self.default_org, repo_name)

        try:
            repo = self.github_conn.get_repo(repo_name)

            issue = repo.create_issue(
                title,
                body=self.issue_body.format(
                    user=str(msg.frm.nick), channel=str(msg.to)
                ),
            )
        except UnknownObjectException:
            return "The specified repository does not exist: {}".format(repo_name)

        return issue.html_url

    @webhook("/github", raw=True)
    def notification(self, request):

        if not getattr(self.bot_config, "GITHUB_RELAY"):
            logging.info("Can't continue without bot_config.GITHUB_RELAY")
            return

        github_event = request.get_header("X-GitHub-Event", None)

        if github_event not in [
            "commit_comment",  # https://developer.github.com/v3/activity/events/types/#commitcommentevent
            "issues",  # https://developer.github.com/v3/activity/events/types/#issuesevent
            "issue_comment",  # https://developer.github.com/v3/activity/events/types/#issuecommentevent
            "pull_request",  # https://developer.github.com/v3/activity/events/types/#pullrequestevent
            "push",  # https://developer.github.com/v3/activity/events/types/#pushevent
        ]:
            logging.info("Unsupported event: {}".format(github_event))
            return

        payload = request.json

        try:
            repo_name = payload["repository"]["name"]
        except KeyError:
            logging.info("Payload does not contain a repository name")
            return

        channel = self.bot_config.GITHUB_RELAY.get(repo_name)
        if not channel:
            # attempt default
            channel = self.bot_config.GITHUB_RELAY.get("_default")
            if not channel:
                logging.info("No default channel found; abort")
                return

        message = self._format_event(github_event, payload)
        self.send(self.build_identifier(channel), message)

    def _format_event(self, event_type, data):
        try:
            return EVENT_DESCRIPTIONS[event_type].format(**data)
        except KeyError:
            return event_type


# some of thee are unused
EVENT_DESCRIPTIONS = {
    "commit_comment": "{comment[user][login]} commented on {comment[commit_id]} in {repository[full_name]}",
    "create": "{sender[login]} created {ref_type} ({ref}) in {repository[full_name]}",
    "delete": "{sender[login]} deleted {ref_type} ({ref}) in {repository[full_name]}",
    "fork": "{forkee[owner][login]} forked {forkee[name]}",
    "gollum": "{sender[login]} edited wiki pages in {repository[full_name]}",
    "issue_comment": "{sender[login]} commented on issue #{issue[number]} in {repository[full_name]}",
    "issues": "{sender[login]} {action} issue #{issue[number]} in {repository[full_name]}",
    "member": "{sender[login]} {action} member {member[login]} in {repository[full_name]}",
    "membership": "{sender[login]} {action} member {member[login]} to team {team[name]} in {repository[full_name]}",
    "page_build": "{sender[login]} built pages in {repository[full_name]}",
    "ping": "ping from {sender[login]}",
    "public": "{sender[login]} publicized {repository[full_name]}",
    "pull_request": "{sender[login]} {action} pull #{pull_request[number]} in {repository[full_name]}",
    "pull_request_review": "{sender[login]} {action} {review[state]} review on pull #{pull_request[number]} in {repository[full_name]}",
    "pull_request_review_comment": "{comment[user][login]} {action} comment on pull #{pull_request[number]} in {repository[full_name]}",
    "push": "{pusher[name]} pushed {ref} in {repository[full_name]} {compare}",
    "release": "{release[author][login]} {action} {release[tag_name]} in {repository[full_name]}",
    "repository": "{sender[login]} {action} repository " "{repository[full_name]}",
    "status": "{sender[login]} set {sha} status to {state} in {repository[full_name]}",
    "team_add": "{sender[login]} added repository {repository[full_name]} to team {team[name]}",
    "watch": "{sender[login]} {action} watch in repository " "{repository[full_name]}",
}
