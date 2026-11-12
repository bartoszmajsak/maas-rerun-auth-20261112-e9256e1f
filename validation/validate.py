#!/usr/bin/env python3
"""Real two-account GitHub validation. Default mode only prints the plan.

Requires gh authentication for both users. --run creates NEW PUBLIC fixture
repositories, fixture PRs/comments, and temporarily grants/revokes fixture access.
No production repositories or their settings are changed. Credentials are read
from gh's credential store into memory, never printed or written to evidence.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


SOURCE = "bartoszmajsak/maas-billing"
REVISION = "cd072a9a3533809fab69429ace384823c521eb55"
MARKER = "Disposable MaaS two-account retry validation"
DENIAL = "Retrying repository-owned branches or cancelled workflows requires current repository write access; ask a maintainer"
FIXTURE = """name: Retry Permission Fixture
on:
  pull_request:
    types: [opened, synchronize]
permissions: {}
jobs:
  fixture:
    runs-on: ubuntu-latest
    timeout-minutes: 4
    permissions:
      contents: write
    steps:
      - name: Controlled result
        env:
          FIXTURE_TITLE: ${{ github.event.pull_request.title }}
        run: |
          if [ "$GITHUB_RUN_ATTEMPT" -gt 1 ]; then exit 0; fi
          if [[ "$FIXTURE_TITLE" == *cancel* ]]; then sleep 120; fi
          exit 1
"""


class ApiError(RuntimeError):
    def __init__(self, method, endpoint, result):
        match = re.search(r"HTTP (\d{3})", result.stderr)
        self.status = int(match.group(1)) if match else None
        try:
            message = json.loads(result.stdout).get("message", "request failed")
        except (ValueError, AttributeError):
            message = "request failed; check connectivity and account authentication"
        super().__init__(f"{method} {endpoint}: HTTP {self.status}: {message}")


class Account:
    def __init__(self, login):
        self.login = login
        env = dict(os.environ)
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"):
            env.pop(key, None)
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com", "--user", login],
            env=env, text=True, capture_output=True, timeout=45,
        )
        if result.returncode or not result.stdout.strip():
            raise RuntimeError(f"Authenticate {login} in gh first (web login, additional workflow scope)")
        self.env = env | {"GH_TOKEN": result.stdout.strip(), "GH_HOST": "github.com", "GH_PAGER": "cat"}
        identity = self.api("GET", "user")
        if identity["login"].lower() != login.lower():
            raise RuntimeError(f"Credential identity does not match {login}")
        self.id = identity["id"]

    def command(self, args, payload=None):
        return subprocess.run(
            ["gh", *args], env=self.env,
            input=json.dumps(payload) if payload is not None else None,
            text=True, capture_output=True, timeout=60,
        )

    def api(self, method, endpoint, payload=None):
        args = ["api", "--hostname", "github.com", "--method", method, endpoint]
        if payload is not None:
            args += ["--input", "-"]
        result = self.command(args, payload)
        if result.returncode:
            raise ApiError(method, endpoint, result)
        return json.loads(result.stdout) if result.stdout.strip() else None


class Validation:
    def __init__(self, owner, outsider, output, seed_repo=None):
        self.owner, self.outsider = owner, outsider
        if owner.id == outsider.id:
            raise RuntimeError("Validation requires two distinct human identities")
        self.output = output
        self.output.mkdir(parents=True, exist_ok=False)
        self.repo = None
        self.prs = []
        self.granted = False
        self.seed_repo = seed_repo
        self.report = {"source": SOURCE, "revision": REVISION,
                       "identities": {owner.login: owner.id, outsider.login: outsider.id},
                       "checks": [], "status": "running"}

    def save(self):
        (self.output / "results.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def wait(self, description, probe, seconds=600):
        deadline = time.monotonic() + seconds
        print(f"Waiting: {description}", flush=True)
        while time.monotonic() < deadline:
            result = probe()
            if result:
                return result
            time.sleep(5)
        raise RuntimeError(f"Timed out: {description}; evidence is in {self.output}")

    def check(self, name, **evidence):
        self.report["checks"].append({"name": name, "result": "pass", **evidence})
        self.save()
        print(f"PASS: {name}", flush=True)

    def head(self):
        return self.owner.api("GET", f"repos/{self.repo}/git/ref/heads/{self.branch}")["object"]["sha"]

    def permission(self):
        return self.owner.api("GET", f"repos/{self.repo}/collaborators/{self.outsider.login}/permission")

    def source_file(self, path):
        data = self.owner.api("GET", f"repos/{SOURCE}/contents/{path}?ref={REVISION}")
        return base64.b64decode(data["content"]).decode()

    def fixture_pr(self, label, fork=False):
        account = self.outsider if fork else self.owner
        repository = self.fork if fork else self.repo
        branch = "fixture-" + label
        account.api("POST", f"repos/{repository}/git/refs",
                    {"ref": "refs/heads/" + branch, "sha": self.head()})
        changed = account.api("PUT", f"repos/{repository}/contents/fixtures/{label}.txt", {
            "branch": branch, "message": "test: " + label,
            "content": base64.b64encode((label + "\n").encode()).decode(),
        })
        pr = account.api("POST", f"repos/{self.repo}/pulls", {
            "base": self.branch, "head": f"{account.login}:{branch}",
            "title": "test: " + label, "body": "Harmless automated permission fixture.",
        })
        self.prs.append(pr["number"])
        return {"number": pr["number"], "sha": changed["commit"]["sha"], "branch": branch}

    def fixture_run(self, pr):
        def probe():
            runs = self.owner.api("GET", f"repos/{self.repo}/actions/workflows/fixture.yml/runs?event=pull_request&head_sha={pr['sha']}&per_page=100")
            return next((r for r in runs["workflow_runs"] if r["head_branch"] == pr["branch"]), None)
        return self.wait(f"PR {pr['number']} fixture run", probe)

    def completed(self, run_id, attempt=1):
        def probe():
            run = self.owner.api("GET", f"repos/{self.repo}/actions/runs/{run_id}")
            return run if run["run_attempt"] >= attempt and run["status"] == "completed" else None
        return self.wait(f"run {run_id}, attempt {attempt} completion", probe)

    def logs(self, run, label):
        result = self.owner.command(["run", "view", str(run["id"]), "--repo", self.repo,
                                     "--attempt", str(run["run_attempt"]), "--log"])
        if result.returncode:
            raise RuntimeError(f"Could not retrieve run {run['id']} logs")
        (self.output / (label + ".log")).write_text(result.stdout)
        return result.stdout

    def retry(self, account, pr, run, allow, association=None):
        assert run["status"] == "completed" and run["conclusion"] in ("failure", "cancelled")
        endpoint = f"repos/{self.repo}/actions/workflows/rerun.yml/runs?event=issue_comment&per_page=100"
        before = {r["id"] for r in self.owner.api("GET", endpoint)["workflow_runs"]}
        tag = "validation-" + uuid.uuid4().hex
        comment = account.api("POST", f"repos/{self.repo}/issues/{pr['number']}/comments",
                              {"body": "/rerun-failed\r\n" + tag})
        assert comment["user"]["id"] == account.id
        if association:
            assert comment["author_association"] == association, comment["author_association"]

        def probe():
            candidates = self.owner.api("GET", endpoint)["workflow_runs"]
            return next((r for r in candidates if r["id"] not in before and r["actor"]["id"] == account.id), None)
        controller = self.wait(f"controller for comment {comment['id']}", probe)
        controller = self.completed(controller["id"])
        log = self.logs(controller, f"controller-{controller['id']}")
        assert tag in log, "Controller log did not match the exact posted comment"
        if allow:
            assert controller["conclusion"] == "success", controller["html_url"]
            target = self.completed(run["id"], run["run_attempt"] + 1)
            assert target["run_attempt"] == run["run_attempt"] + 1
            assert target["conclusion"] == "success", target["html_url"]
            assert target["actor"]["id"] == run["actor"]["id"]
        else:
            assert controller["conclusion"] == "failure", controller["html_url"]
            assert any(DENIAL in line and 'echo "' not in line for line in log.splitlines()), "Expected explicit permission denial"
            target = self.owner.api("GET", f"repos/{self.repo}/actions/runs/{run['id']}")
            assert (target["run_attempt"], target["status"], target["conclusion"]) == (
                run["run_attempt"], run["status"], run["conclusion"])
        self.check(f"{account.login} {'allowed' if allow else 'denied'} on PR {pr['number']}",
                   comment=comment["html_url"], association=comment["author_association"],
                   controller=controller["html_url"], target=target["html_url"],
                   before_attempt=run["run_attempt"], after_attempt=target["run_attempt"])
        return controller, target

    def failed(self, pr):
        run = self.completed(self.fixture_run(pr)["id"])
        assert run["conclusion"] == "failure" and run["run_attempt"] == 1
        return run

    def setup(self):
        if self.seed_repo:
            self.resume_seed()
            return
        name = "maas-rerun-auth-" + datetime.now(timezone.utc).strftime("%Y%m%d-") + uuid.uuid4().hex[:8]
        repo = self.owner.api("POST", "user/repos", {
            "name": name, "description": MARKER, "private": False, "auto_init": True,
        })
        self.repo, self.branch = repo["full_name"], repo["default_branch"]
        assert self.repo == f"{self.owner.login}/{name}" and not repo["private"]
        self.report["repository"] = repo["html_url"]
        self.save()
        print("Created PUBLIC fixture: " + repo["html_url"], flush=True)
        self.owner.api("PUT", f"repos/{self.repo}/actions/permissions/workflow",
                       {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": True})
        self.owner.api("PUT", f"repos/{self.repo}/actions/permissions/fork-pr-contributor-approval",
                       {"approval_policy": "first_time_contributors"})
        fork = self.outsider.api("POST", f"repos/{self.repo}/forks", {"default_branch_only": True})
        self.fork = fork["full_name"]
        def fork_ready():
            try:
                return self.outsider.api("GET", f"repos/{self.fork}/git/ref/heads/{self.branch}")
            except ApiError as exc:
                if exc.status not in (404, 409):
                    raise
                return None
        self.wait("test account fork ready", fork_ready)
        # Establish real CONTRIBUTOR status before installing any CI workflows.
        seed = self.fixture_pr("seed-contribution", fork=True)
        self.wait("seed contribution mergeability", lambda: self.owner.api(
            "GET", f"repos/{self.repo}/pulls/{seed['number']}").get("mergeable") is True)
        merged = self.owner.api("PUT", f"repos/{self.repo}/pulls/{seed['number']}/merge", {"merge_method": "merge"})
        assert merged["merged"] is True
        assert self.permission()["permission"] not in ("write", "admin")
        self.wait("contributor association propagation", lambda: self.owner.api(
            "GET", f"repos/{self.repo}/pulls/{seed['number']}")["author_association"] == "CONTRIBUTOR")
        confirmation = self.outsider.api("POST", f"repos/{self.repo}/issues/{seed['number']}/comments",
                                         {"body": "Confirming contributor identity for permission validation."})
        assert confirmation["author_association"] == "CONTRIBUTOR", confirmation["author_association"]
        self.check("real contributor identity without write access", comment=confirmation["html_url"])
        self.install()

    def resume_seed(self):
        if not self.seed_repo.startswith(self.owner.login + "/maas-rerun-auth-"):
            raise RuntimeError("Resume only accepts newly created validation fixtures")
        repo = self.owner.api("GET", f"repos/{self.seed_repo}")
        if repo["owner"]["id"] != self.owner.id or repo["private"] or repo["description"] != MARKER:
            raise RuntimeError("Repository is not an owned public validation fixture")
        self.repo, self.branch = repo["full_name"], repo["default_branch"]
        self.fork = self.outsider.login + "/" + repo["name"]
        fork = self.outsider.api("GET", f"repos/{self.fork}")
        assert fork["parent"]["id"] == repo["id"] and fork["owner"]["id"] == self.outsider.id
        tree = self.owner.api("GET", f"repos/{self.repo}/git/trees/{self.head()}?recursive=1")
        if any(item["path"].startswith(".github/workflows/") for item in tree["tree"]):
            raise RuntimeError("Seed resume requires a fixture with no workflows installed yet")
        pulls = self.owner.api("GET", f"repos/{self.repo}/pulls?state=all&per_page=100")
        seed = next(pr for pr in pulls if pr["head"]["ref"] == "fixture-seed-contribution"
                    and pr["user"]["id"] == self.outsider.id and pr["merged_at"])
        self.prs = [seed["number"]]
        self.report["repository"] = repo["html_url"]
        self.wait("contributor association propagation", lambda: self.owner.api(
            "GET", f"repos/{self.repo}/pulls/{seed['number']}")["author_association"] == "CONTRIBUTOR")
        assert self.permission()["permission"] not in ("write", "admin")
        comment = self.outsider.api("POST", f"repos/{self.repo}/issues/{seed['number']}/comments",
                                    {"body": "Confirming propagated contributor identity before CI validation."})
        assert comment["author_association"] == "CONTRIBUTOR"
        self.check("real contributor identity without write access", comment=comment["html_url"])
        self.install()

    def install(self):
        files = {path: self.source_file(path) for path in (
            ".github/workflows/rerun.yml", ".github/workflows/rerun-help.yml", "CONTRIBUTING.md")}
        self.report["workflow_sha256"] = {path: hashlib.sha256(content.encode()).hexdigest()
                                           for path, content in files.items() if path.endswith(".yml")}
        files[".github/workflows/fixture.yml"] = FIXTURE
        parent = self.head()
        commit = self.owner.api("GET", f"repos/{self.repo}/git/commits/{parent}")
        tree = self.owner.api("POST", f"repos/{self.repo}/git/trees", {
            "base_tree": commit["tree"]["sha"],
            "tree": [{"path": path, "mode": "100644", "type": "blob", "content": content}
                     for path, content in files.items()],
        })
        installed = self.owner.api("POST", f"repos/{self.repo}/git/commits", {
            "message": "test: install exact reviewed retry workflows", "tree": tree["sha"], "parents": [parent],
        })
        self.owner.api("PATCH", f"repos/{self.repo}/git/refs/heads/{self.branch}", {"sha": installed["sha"]})
        self.report["fixture_default_commit"] = installed["sha"]
        self.save()
        self.wait("retry workflow registered", lambda: self.workflow_ready())

    def workflow_ready(self):
        try:
            return self.owner.api("GET", f"repos/{self.repo}/actions/workflows/rerun.yml")
        except ApiError as exc:
            if exc.status != 404:
                raise
            return None

    def run(self):
        try:
            self.setup()
            fork_pr = self.fixture_pr("fork-failure", fork=True)
            failure = self.failed(fork_pr)
            # Verify notifier delivery before making this failed run successful.
            def help_comment():
                comments = self.owner.api("GET", f"repos/{self.repo}/issues/{fork_pr['number']}/comments?per_page=100")
                return next((c for c in comments if c["user"]["login"] == "github-actions[bot]"
                             and "<!-- maas-rerun-help -->" in c["body"] and str(failure["id"]) in c["body"]), None)
            help_post = self.wait("correct fork PR help comment", help_comment)
            self.check("fork notification resolves correct PR", comment=help_post["html_url"])
            _, retried = self.retry(self.outsider, fork_pr, failure, True, "CONTRIBUTOR")
            log = self.logs(retried, "fork-token-permissions")
            assert "Contents: read" in log and "Contents: write" not in log
            assert "Secret source: None" in log
            self.check("fork rerun retains read-only token", run=retried["html_url"])

            same_pr = self.fixture_pr("same-repo-failure")
            failure = self.failed(same_pr)
            self.retry(self.outsider, same_pr, failure, False, "CONTRIBUTOR")
            self.retry(self.owner, same_pr, failure, True)

            cancel_pr = self.fixture_pr("fork-cancel", fork=True)
            cancel = self.fixture_run(cancel_pr)
            def running():
                jobs = self.owner.api("GET", f"repos/{self.repo}/actions/runs/{cancel['id']}/jobs")["jobs"]
                return any(s["name"] == "Controlled result" and s["status"] == "in_progress"
                           for j in jobs for s in j["steps"])
            self.wait("cancellable fixture step started", running)
            self.owner.api("POST", f"repos/{self.repo}/actions/runs/{cancel['id']}/cancel")
            cancel = self.completed(cancel["id"])
            assert cancel["conclusion"] == "cancelled"
            self.retry(self.outsider, cancel_pr, cancel, False, "CONTRIBUTOR")
            self.retry(self.owner, cancel_pr, cancel, True)

            # Test current authority and replay after authority is revoked.
            self.granted = True  # finally removes access even if the invite/accept step fails.
            self.owner.api("PUT", f"repos/{self.repo}/collaborators/{self.outsider.login}", {"permission": "push"})
            invitations = self.outsider.api("GET", "user/repository_invitations?per_page=100")
            for invitation in invitations:
                if invitation["repository"]["full_name"] == self.repo:
                    self.outsider.api("PATCH", f"user/repository_invitations/{invitation['id']}")
            self.wait("test account write grant effective", lambda: self.permission()["permission"] in ("write", "admin"))
            writer_pr = self.fixture_pr("temporary-writer")
            failure = self.failed(writer_pr)
            writer_controller, _ = self.retry(self.outsider, writer_pr, failure, True)
            self.owner.api("DELETE", f"repos/{self.repo}/collaborators/{self.outsider.login}")
            self.wait("test account write grant revoked", lambda: self.permission()["permission"] not in ("write", "admin"))
            self.granted = False
            revoked_pr = self.fixture_pr("revoked-writer")
            self.retry(self.outsider, revoked_pr, self.failed(revoked_pr), False, "CONTRIBUTOR")
            self.owner.api("POST", f"repos/{self.repo}/actions/runs/{writer_controller['id']}/rerun")
            replay = self.completed(writer_controller["id"], 2)
            log = self.logs(replay, "revoked-old-comment-replay")
            assert replay["conclusion"] == "failure"
            assert any(DENIAL in line and 'echo "' not in line for line in log.splitlines())
            self.check("old authorized comment rechecked after revocation", controller=replay["html_url"])
            self.report["status"] = "pass"
        except Exception as exc:
            self.report["status"] = "failed"
            self.report["error"] = str(exc)
            raise
        finally:
            errors = []
            if self.repo:
                if self.granted:
                    try:
                        self.owner.api("DELETE", f"repos/{self.repo}/collaborators/{self.outsider.login}")
                        invitations = self.owner.api("GET", f"repos/{self.repo}/invitations?per_page=100")
                        for invitation in invitations:
                            if (invitation.get("invitee") or {}).get("id") == self.outsider.id:
                                self.owner.api("DELETE", f"repos/{self.repo}/invitations/{invitation['id']}")
                        assert self.permission()["permission"] not in ("write", "admin")
                    except Exception as exc:
                        errors.append("Remove temporary fixture access: " + str(exc))
                for number in self.prs:
                    try:
                        pr = self.owner.api("GET", f"repos/{self.repo}/pulls/{number}")
                        if pr["state"] == "open":
                            self.owner.api("PATCH", f"repos/{self.repo}/pulls/{number}", {"state": "closed"})
                    except Exception as exc:
                        errors.append(f"Close fixture PR {number}: {exc}")
            self.report["cleanup_errors"] = errors
            if errors:
                self.report["status"] = "failed"
            self.save()
            if errors:
                raise RuntimeError("; ".join(errors))


def main():
    if not __debug__:
        raise RuntimeError("Run without -O: validation assertions must remain enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="bartoszmajsak")
    parser.add_argument("--contributor", default="bartoszmajsak-test")
    parser.add_argument("--check-auth", action="store_true", help="read-only credential/identity check")
    parser.add_argument("--run", action="store_true", help="create a NEW PUBLIC fixture and execute the matrix")
    parser.add_argument("--resume-seed", help="resume an owned validation fixture after seed propagation, before CI installation")
    parser.add_argument("--output", type=Path, default=Path("rerun-validation-" + uuid.uuid4().hex[:8]))
    args = parser.parse_args()
    if not (args.check_auth or args.run):
        print(f"Plan: owner={args.owner}, contributor={args.contributor}, reviewed source={REVISION}")
        print("--check-auth verifies both stored gh credentials without writes.")
        print("--run creates new public fixture/fork repositories, fixture PRs/comments,")
        print("temporarily grants/revokes fixture write access, and saves evidence.")
        print("It leaves repositories available for inspection, closes fixture PRs,")
        print("and removes temporary write access. It never changes production repos.")
        return
    owner, contributor = Account(args.owner), Account(args.contributor)
    print(f"Verified accounts: {owner.login} ({owner.id}), {contributor.login} ({contributor.id})")
    if args.run:
        validation = Validation(owner, contributor, args.output, args.resume_seed)
        validation.run()
        print(f"Result: {validation.report['status']}; evidence: {args.output / 'results.json'}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as exc:
        print(f"Validation stopped: {exc}", file=sys.stderr)
        sys.exit(1)
