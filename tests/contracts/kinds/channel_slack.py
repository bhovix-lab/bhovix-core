"""The `slack` channel kind against a local fake Slack API (the factory itself refuses non-https)."""

from hadavin_sdk.approvals.slack_channel import SlackChannel
from tests.contracts.kinds import kind
from tests.fixtures.fake_slack import FakeSlack

TOKEN = "xoxb" + "-contract-fake"  # built from parts


@kind("channel", "slack")
def slack(tmp_path, signing_secret):
    api = FakeSlack().start()
    try:
        yield SlackChannel("C0CONTRACT", TOKEN, signing_secret, api_base=api.api_base, timeout_s=5)
    finally:
        api.stop()
