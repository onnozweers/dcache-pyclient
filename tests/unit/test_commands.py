"""Unit tests for CLI commands."""

from argparse import Namespace
from contextlib import contextmanager
from unittest.mock import patch

from ada.auth import TokenAuth
from ada.cli import commands


class _FakeClient:
    def __init__(self, token: str) -> None:
        self.auth = TokenAuth(token, source="$BEARER_TOKEN")

    def view_token(self) -> dict:
        return self.auth.view_token()


def _run_viewtoken(token: str, capsys) -> str:
    @contextmanager
    def fake_get_client(parsed_args):
        yield _FakeClient(token)

    with patch.object(commands, "__get_client__", fake_get_client):
        commands.viewtoken(Namespace(minimal=False))
    return capsys.readouterr().out


class TestViewtokenIpCaveat:
    def test_jwt_no_ip_caveat_warning(self, make_jwt_token, capsys):
        out = _run_viewtoken(make_jwt_token(), capsys)
        assert "IP caveat" not in out

    def test_macaroon_without_ip_warns(self, make_macaroon_token, capsys):
        out = _run_viewtoken(make_macaroon_token(before="2099-01-01T00:00:00.000Z"), capsys)
        assert "IP caveat: empty. Warning" in out

    def test_macaroon_with_ip_is_checked(self, make_macaroon_token, capsys):
        token = make_macaroon_token(before="2099-01-01T00:00:00.000Z", ip="203.0.113.0/24")
        with patch("ada.auth.check_ip_caveat", return_value="ok") as check:
            out = _run_viewtoken(token, capsys)
        check.assert_called_once_with("203.0.113.0/24")
        assert "IP caveat: ok" in out
