import re
import hmac
import hashlib
import urllib.parse as urlparse
import json

from errbot import BotPlugin, botcmd, webhook
from flask import abort
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

    # some of these are unused
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
        "watch": "{sender[login]} {action} watch in repository "
        "{repository[full_name]}",
    }

    def get_configuration_template(self):
        return {
            "ORG": "facultyco",
            "DEFAULT_CHANNEL": "faculty",
            "WEBHOOK_SECRET": "qqq111qq22q3nicetry!",
            "TOKEN": "nope.",
        }

    def activate(self):

        if not self.config:
            self.log.info("Not configured. Forbidding activation.")
            return
        self.github_conn = github.Github(self.config["TOKEN"])

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

        super().activate()

    def _get_issue(self, channel_id, match):
        repo_name = match.group(1)
        issue_id = int(match.group(2))
        self.log.debug("Retrieving issue {} from {}".format(issue_id, repo_name))

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
        self.log.debug("Retrieving PR {} from {}".format(pull_id, repo_name))

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
        # Ignore all messages from the bot itself
        if msg.frm == self.bot_identifier:
            return

        if msg.is_direct:
            reply_to = msg.frm
        else:
            reply_to = msg.to

        for pattern in self.patterns.keys():
            match = re.search(
                self.patterns[pattern]["pattern"], msg.body, re.IGNORECASE
            )
            if match is not None:
                self.patterns[pattern]["callback"](reply_to, match)

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

        repo_name = args.split(" ")[0]
        title = " ".join(args.split(" ")[1:])

        try:
            repo_name.index("/")
        except ValueError:
            repo_name = "{}/{}".format(self.config["ORG"], repo_name)

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

    def _has_valid_sig(self, request):
        data = request.stream.read()
        sig = request.headers.get("X-Hub-Signature")

        digest = hmac.new(
            self.config["WEBHOOK_SECRET"].encode("utf-8"), data, hashlib.sha1,
        ).hexdigest()

        if sig is None:
            self.log.debug("No signature")
            return False

        sig_parts = sig.split("=", 1)
        if not isinstance(digest, str):
            digest = str(digest)

        if (
            len(sig_parts) < 2
            or sig_parts[0] != "sha1"
            or not hmac.compare_digest(sig_parts[1], digest)
        ):
            self.log.debug("Invalid signature")
            return False

        self.log.debug("Valid signature.")
        return data

    @webhook("/github/<channel>", raw=True)
    def notification(self, request, channel):

        github_event = request.headers.get("X-GitHub-Event", None)

        if self.config["WEBHOOK_SECRET"]:
            # we only care to validate the sig if there's a secret set
            req_data = self._has_valid_sig(request)
            if not req_data:
                self.log.warn("Invalid signature in request; not relaying")
                abort(403)
        else:
            req_data = request.stream.read()

        # need to do it this way because of the raw request + hash
        payload = json.loads(req_data)

        if not channel:
            channel = self.config["DEFAULT_CHANNEL"]

        channel = f"#{channel}"
        found_channel = False
        for room in self.rooms():
            if room.room == channel:
                found_channel = True
                break
        if not found_channel:
            self.log.warn("Can't relay to non-present channels.")
            abort(404)

        self.log.info(f"Relaying to {channel}")

        target = self.build_identifier(channel)

        if github_event in ["push", "create", "delete"]:
            branch_name = payload.get("ref", "").split("/")[-1]
            try:
                base_ref_name = payload.get("base_ref", "").split("/")[-1]
            except Exception:
                base_ref_name = None

            distinct_commits = [
                commit
                for commit in payload.get("commits", [])
                if commit.get("distinct")
            ]
            message_pieces = []

            submitter = payload.get("pusher", {}).get("name")
            if not submitter:
                submitter = payload.get("sender", {}).get("login")

            if submitter:
                message_pieces.append(self._format_name(submitter))

            if payload.get("created"):
                if payload.get("tag"):
                    message_pieces.append(
                        "{} {} as {}".format(
                            self._bold("tagged"),
                            self._format_branch(base_ref_name)
                            if base_ref_name
                            else self._format_hash(payload["after"][:8]),
                            payload["tag_name"],
                        )
                    )

                else:
                    message_pieces.append(
                        "{} {}".format(self._bold("created"), branch_name)
                    )
                    if payload.get("base_ref"):
                        message_pieces.append(
                            "from {}".format(self._format_branch(base_ref_name))
                        )
                    elif not distinct_commits:
                        message_pieces.append(
                            "at {}".format(self._format_hash(payload["after"][:8]))
                        )

                    message_pieces.append(
                        "(+{} new commit{})".format(
                            self._bold(len(distinct_commits)),
                            "" if len(distinct_commits) == 1 else "s",
                        )
                    )

            elif payload.get("deleted"):
                message_pieces.append(
                    "{} {} at {}".format(
                        self._bold(self._color_string("red", "deleted")),
                        self._format_branch(branch_name),
                        self._format_hash(payload["before"][:8]),
                    )
                )

            elif payload.get("forced"):
                message_pieces.append(
                    "{} {} from {} to {}".format(
                        self._bold(self._color_string("red", "force-pushed")),
                        self._format_branch(branch_name),
                        self._format_hash(payload["before"][:8]),
                        self._format_hash(payload["after"][:8]),
                    )
                )

            elif payload.get("commits") and not distinct_commits:
                if payload.get("base_ref"):
                    message_pieces.append(
                        "merged {} into {}".format(
                            self._format_branch(base_ref_name),
                            self._format_branch(branch_name),
                        )
                    )
                else:
                    message_pieces.append(
                        "fast-forwarded {} from {} to {}".format(
                            self._format_branch(branch_name),
                            self._format_hash(payload["before"][:8]),
                            self._format_hash(payload["after"][:8]),
                        )
                    )

            elif not distinct_commits:
                return

            else:
                message_pieces.append(
                    "pushed {} new commit{} to {}".format(
                        self._bold(len(distinct_commits)),
                        "" if len(distinct_commits) == 1 else "s",
                        self._format_branch(branch_name),
                    )
                )

            url = payload.get("compare", payload["repository"]["html_url"])
            self._send_with_repo_and_url(
                target, " ".join(message_pieces), payload["repository"]["name"], url
            )

            for commit in distinct_commits[-3:]:
                self._send_commit_message(
                    target, payload["repository"]["name"], branch_name, commit
                )

        elif github_event == "issues":
            if payload["action"] not in ["opened", "closed"]:
                return
            message = "{} {} issue #{}: {}".format(
                self._format_name(payload["sender"]["login"]),
                payload["action"],
                payload["issue"]["number"],
                payload["issue"]["title"],
            )

            self._send_with_repo_and_url(
                target,
                message,
                payload["repository"]["name"],
                payload["issue"]["html_url"],
            )

        elif github_event == "issue_comment":
            short = self._short_message(payload["comment"]["body"])
            if short != payload["comment"]["body"]:
                short = "{}...".format(short)

            issue_type = "issue"
            if payload["issue"].get("pull_request"):
                issue_type = "pull request"

            action = "commented"
            if payload["action"] == "edited":
                action = "edited comment"
            elif payload["action"] == "deleted":
                action = "deleted comment"

            message = "{} {} on {} #{}: {}".format(
                self._format_name(payload["sender"]["login"]),
                action,
                issue_type,
                payload["issue"]["number"],
                short,
            )

            self._send_with_repo_and_url(
                target,
                message,
                payload["repository"]["name"],
                payload["comment"]["html_url"],
            )

        elif github_event == "commit_comment":

            short = self._short_message(payload["comment"]["body"])
            if short != payload["comment"]["body"]:
                short = "{}...".format(short)

            message = "{} commented on commit {}: {}".format(
                self._format_name(payload["sender"]["login"]),
                payload["comment"]["commit_id"][:8],
                short,
            )

            self._send_with_repo_and_url(
                target,
                message,
                payload["repository"]["name"],
                payload["comment"]["html_url"],
            )

        elif github_event == "pull_request":
            if payload["action"] in ["labeled", "unlabeled"]:
                self._pull_request_labeled(target, payload)
            elif payload["action"] not in [
                "assigned",
                "synchronize",
                "review_requested",
                "edited",
            ]:
                self._pull_request_default(target, payload)

        elif github_event == "pull_request_review_comment":

            short = self._short_message(payload["comment"]["body"])
            if short != payload["comment"]["body"]:
                short = "{}...".format(short)

            message = "{} commented on PR #{} {}: {}".format(
                self._format_name(payload["sender"]["login"]),
                payload["pull_request"]["number"],
                payload["comment"]["commit_id"][:8],
                short,
            )

            self._send_with_repo_and_url(
                target,
                message,
                payload["repository"]["name"],
                payload["comment"]["html_url"],
            )

        elif github_event == "ping":

            message = "[{}] {} initiated a webhook test: {}".format(
                self._format_repo(payload["repository"]["name"]),
                self._format_name(payload["sender"]["login"]),
                payload["zen"],
            )

            self.send(target, message)

        else:
            self.log.warn("Unsupported event: {}".format(github_event))
            self.log.info(self._format_event(github_event, payload))
            return

    def _send_with_repo_and_url(self, target, message, repo_name, url):
        message = "[{}] {} {}".format(
            self._format_repo(repo_name), message, self.shorten_url(url)
        )
        self.send(target, message)

    def _send_commit_message(self, target, repo_name, branch, commit):
        short = self._short_message(commit["message"])
        if short != commit["message"]:
            short = "{}...".format(short)

        message = "{}/{} {} {}: {}".format(
            self._format_repo(repo_name),
            self._format_branch(branch),
            self._format_hash(commit["id"][:8]),
            self._format_name(commit["author"]["name"]),
            short,
        )

        self.send(target, message)

    @staticmethod
    def _short_message(message):
        text = message.replace("\r", "\n").replace("\n\n", "\n").split("\n")[0]
        return text

    def _format_event(self, event_type, payload):
        try:
            return self.EVENT_DESCRIPTIONS[event_type].format(**payload)
        except KeyError:
            return event_type

    def _pull_request_labeled(self, target, payload):
        labels = [label["name"] for label in payload["pull_request"]["labels"]]
        if labels:
            message = "{} changed labels on PR #{} to {}".format(
                self._format_name(payload["sender"]["login"]),
                payload["number"],
                " ".join(labels),
            )
        else:
            message = "{} removed all labels on PR #{}".format(
                self._format_name(payload["sender"]["login"]), payload["number"]
            )

        self._send_with_repo_and_url(
            target,
            message,
            payload["repository"]["name"],
            payload["pull_request"]["html_url"],
        )

    def _pull_request_default(self, target, payload):
        base_ref = payload["pull_request"]["base"]["label"].split(":")[-1]
        head_ref = payload["pull_request"]["head"]["label"].split(":")[-1]

        message = "{} {} pull request #{}: {} ({}...{})".format(
            self._format_name(payload["sender"]["login"]),
            payload["action"],
            payload["number"],
            payload["pull_request"]["title"],
            self._format_branch(base_ref),
            self._format_branch(head_ref),
        )

        self._send_with_repo_and_url(
            target,
            message,
            payload["repository"]["name"],
            payload["pull_request"]["html_url"],
        )

    @staticmethod
    def _bold(string):
        return "**{}**".format(string)

    @staticmethod
    def _italic(string):
        return "*{}*".format(string)

    @staticmethod
    def _underline(string):
        return "_{}_".format(string)

    @staticmethod
    def _color_string(color, string):
        return "`" + string + "`{:color='" + color + "'}"

    def _format_url(self, url):
        return self._color_string("cyan", url)

    def _format_repo(self, repo_name):
        return self._color_string("magenta", repo_name)

    def _format_name(self, name):
        return self._color_string("cyan", name)

    def _format_branch(self, branch):
        return self._color_string("magenta", branch)

    def _format_tag(self, tag):
        return self._format_branch(tag)

    def _format_hash(self, hsh):
        return self._color_string("blue", hsh)

    @staticmethod
    def _remove_utm(url):
        parsed = urlparse.urlparse(url)
        params = urlparse.parse_qs(parsed.query)
        clean_params = {}
        for param in params.keys():
            if not param.startswith("utm_"):
                clean_params.update({param: params[param]})

        return urlparse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                "&".join(
                    [
                        "{}={}".format(key, clean_params[key])
                        for key in clean_params.keys()
                    ]
                ),
                parsed.fragment,
            )
        )

    @staticmethod
    def shorten_url(url):
        # no short for you (yet)
        return url
