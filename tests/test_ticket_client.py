"""Tests for scripts.ticket_client — Linear and Trello ticket creation.

All tests use unittest.mock.patch to avoid real HTTP calls.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from scripts.ticket_client import create_linear_ticket, create_ticket, create_trello_card

_VERDICT: dict = {
    "verdict": "high_risk",
    "risk_score": 87,
    "confidence": 82,
    "recommended_action": "Immediately disable account",
    "incident_id": "INC-001",
    "user": "alice@example.com",
    "rationale": [
        {"signal": "impossible_travel", "score": 30, "detail": "800 km in 10 min"},
        {"signal": "mfa_fatigue", "score": 25, "detail": "5 denials"},
    ],
}

_LINEAR_ENV = {
    "ADTE_LINEAR_API_KEY": "lin_api_key",
    "ADTE_LINEAR_TEAM_ID": "team-abc",
}

_TRELLO_ENV = {
    "ADTE_TRELLO_API_KEY": "trello_key",
    "ADTE_TRELLO_TOKEN": "trello_token",
    "ADTE_TRELLO_LIST_ID": "list-123",
}


class TestCreateLinearTicket(unittest.TestCase):
    """Tests for create_linear_ticket."""

    @patch("scripts.ticket_client.requests.post")
    def test_success_returns_url(self, mock_post: MagicMock) -> None:
        """Returns the issue URL when Linear responds with 200 and a URL."""
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "data": {"issueCreate": {"issue": {"url": "https://linear.app/issue/123"}}}
        }

        with patch.dict("os.environ", _LINEAR_ENV):
            result = create_linear_ticket(_VERDICT)

        self.assertEqual(result, "https://linear.app/issue/123")
        mock_post.assert_called_once()

    @patch("scripts.ticket_client.requests.post")
    def test_http_error_returns_none(self, mock_post: MagicMock) -> None:
        """Returns None when Linear returns a non-200 HTTP status."""
        mock_post.return_value.status_code = 500

        with patch.dict("os.environ", _LINEAR_ENV):
            result = create_linear_ticket(_VERDICT)

        self.assertIsNone(result)

    @patch("scripts.ticket_client.requests.post")
    def test_missing_api_key_returns_none_without_request(
        self, mock_post: MagicMock
    ) -> None:
        """Returns None immediately when ADTE_LINEAR_API_KEY is not set."""
        with patch.dict("os.environ", {"ADTE_LINEAR_TEAM_ID": "team-abc"}, clear=True):
            result = create_linear_ticket(_VERDICT)

        self.assertIsNone(result)
        mock_post.assert_not_called()

    @patch("scripts.ticket_client.requests.post")
    def test_missing_team_id_returns_none_without_request(
        self, mock_post: MagicMock
    ) -> None:
        """Returns None immediately when ADTE_LINEAR_TEAM_ID is not set."""
        with patch.dict("os.environ", {"ADTE_LINEAR_API_KEY": "key"}, clear=True):
            result = create_linear_ticket(_VERDICT)

        self.assertIsNone(result)
        mock_post.assert_not_called()

    @patch("scripts.ticket_client.requests.post")
    def test_request_exception_returns_none(self, mock_post: MagicMock) -> None:
        """Returns None when requests raises a RequestException."""
        import requests as req_lib
        mock_post.side_effect = req_lib.RequestException("timeout")

        with patch.dict("os.environ", _LINEAR_ENV):
            result = create_linear_ticket(_VERDICT)

        self.assertIsNone(result)


class TestCreateTrelloCard(unittest.TestCase):
    """Tests for create_trello_card."""

    @patch("scripts.ticket_client.requests.post")
    def test_success_returns_url(self, mock_post: MagicMock) -> None:
        """Returns the card URL when Trello responds with 200 and a URL."""
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "shortUrl": "https://trello.com/c/abc123"
        }

        with patch.dict("os.environ", _TRELLO_ENV):
            result = create_trello_card(_VERDICT)

        self.assertEqual(result, "https://trello.com/c/abc123")
        mock_post.assert_called_once()

    @patch("scripts.ticket_client.requests.post")
    def test_http_error_returns_none(self, mock_post: MagicMock) -> None:
        """Returns None when Trello returns a non-200/201 HTTP status."""
        mock_post.return_value.status_code = 400

        with patch.dict("os.environ", _TRELLO_ENV):
            result = create_trello_card(_VERDICT)

        self.assertIsNone(result)

    @patch("scripts.ticket_client.requests.post")
    def test_missing_api_key_returns_none_without_request(
        self, mock_post: MagicMock
    ) -> None:
        """Returns None immediately when ADTE_TRELLO_API_KEY is not set."""
        env = {"ADTE_TRELLO_TOKEN": "tok", "ADTE_TRELLO_LIST_ID": "lst"}
        with patch.dict("os.environ", env, clear=True):
            result = create_trello_card(_VERDICT)

        self.assertIsNone(result)
        mock_post.assert_not_called()

    @patch("scripts.ticket_client.requests.post")
    def test_request_exception_returns_none(self, mock_post: MagicMock) -> None:
        """Returns None when requests raises a RequestException."""
        import requests as req_lib
        mock_post.side_effect = req_lib.RequestException("connection refused")

        with patch.dict("os.environ", _TRELLO_ENV):
            result = create_trello_card(_VERDICT)

        self.assertIsNone(result)


class TestCreateTicketDispatcher(unittest.TestCase):
    """Tests for the create_ticket dispatcher."""

    @patch("scripts.ticket_client.requests.post")
    def test_tries_linear_first_when_both_keys_present(
        self, mock_post: MagicMock
    ) -> None:
        """Calls Linear and returns its URL when both providers are configured."""
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "data": {"issueCreate": {"issue": {"url": "https://linear.app/issue/1"}}}
        }

        with patch.dict("os.environ", {**_LINEAR_ENV, **_TRELLO_ENV}):
            result = create_ticket(_VERDICT)

        self.assertEqual(result, "https://linear.app/issue/1")
        # Linear endpoint was called
        call_url = mock_post.call_args[0][0]
        self.assertIn("linear.app", call_url)

    @patch("scripts.ticket_client.requests.post")
    def test_falls_back_to_trello_when_no_linear_key(
        self, mock_post: MagicMock
    ) -> None:
        """Falls through to Trello when ADTE_LINEAR_API_KEY is not set."""
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "shortUrl": "https://trello.com/c/xyz"
        }

        with patch.dict("os.environ", _TRELLO_ENV, clear=True):
            result = create_ticket(_VERDICT)

        self.assertEqual(result, "https://trello.com/c/xyz")
        call_url = mock_post.call_args[0][0]
        self.assertIn("trello.com", call_url)

    @patch("scripts.ticket_client.requests.post")
    def test_returns_none_when_neither_key_configured(
        self, mock_post: MagicMock
    ) -> None:
        """Returns None silently when no provider keys are set."""
        with patch.dict("os.environ", {}, clear=True):
            result = create_ticket(_VERDICT)

        self.assertIsNone(result)
        mock_post.assert_not_called()

    @patch("scripts.ticket_client.requests.post")
    def test_falls_back_to_trello_when_linear_fails(
        self, mock_post: MagicMock
    ) -> None:
        """Falls through to Trello when Linear returns an error."""
        # First call (Linear) returns 500; second call (Trello) returns 200.
        linear_resp = MagicMock()
        linear_resp.status_code = 500
        trello_resp = MagicMock()
        trello_resp.status_code = 200
        trello_resp.json.return_value = {"shortUrl": "https://trello.com/c/fallback"}
        mock_post.side_effect = [linear_resp, trello_resp]

        with patch.dict("os.environ", {**_LINEAR_ENV, **_TRELLO_ENV}):
            result = create_ticket(_VERDICT)

        self.assertEqual(result, "https://trello.com/c/fallback")
        self.assertEqual(mock_post.call_count, 2)


if __name__ == "__main__":
    unittest.main()
