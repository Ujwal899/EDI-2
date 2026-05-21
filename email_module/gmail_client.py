import base64
import logging
from email.utils import parseaddr
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


logger = logging.getLogger(__name__)

SCOPES: Sequence[str] = ["https://www.googleapis.com/auth/gmail.readonly"]


@dataclass
class EmailMessage:
    email_id: str
    subject: str
    body: str
    sender: str
    sender_domain: str
    html_body: str = ""
    attachments: List[dict] | None = None
    reply_to: str = ""
    return_path: str = ""


def _decode_base64url(data: str) -> str:
    if not data:
        return ""
    padding = "=" * ((4 - len(data) % 4) % 4)
    raw = base64.urlsafe_b64decode(data + padding)
    return raw.decode("utf-8", errors="replace")


def _extract_header(headers: List[dict], name: str) -> str:
    wanted = name.lower()
    for header in headers or []:
        key = str(header.get("name", "")).lower()
        if key == wanted:
            return str(header.get("value", "")).strip()
    return ""


def _extract_text_plain(payload: dict) -> str:
    if not payload:
        return ""

    mime_type = payload.get("mimeType", "")
    body_data = ((payload.get("body") or {}).get("data")) or ""

    if mime_type == "text/plain" and body_data:
        return _decode_base64url(body_data)

    parts = payload.get("parts") or []
    for part in parts:
        part_mime = part.get("mimeType", "")
        if part_mime == "text/plain":
            part_data = ((part.get("body") or {}).get("data")) or ""
            if part_data:
                return _decode_base64url(part_data)

    for part in parts:
        text = _extract_text_plain(part)
        if text:
            return text

    if body_data:
        return _decode_base64url(body_data)

    return ""


def _extract_text_html(payload: dict) -> str:
    if not payload:
        return ""

    mime_type = payload.get("mimeType", "")
    body_data = ((payload.get("body") or {}).get("data")) or ""

    if mime_type == "text/html" and body_data:
        return _decode_base64url(body_data)

    parts = payload.get("parts") or []
    for part in parts:
        html = _extract_text_html(part)
        if html:
            return html

    return ""


def _collect_attachments(payload: dict) -> List[dict]:
    if not payload:
        return []

    attachments: List[dict] = []
    filename = str(payload.get("filename") or "").strip()
    mime_type = str(payload.get("mimeType") or "").strip()
    body = payload.get("body") or {}
    attachment_id = str(body.get("attachmentId") or "")

    if filename or attachment_id:
        attachments.append(
            {
                "filename": filename,
                "mime_type": mime_type,
                "size": int(body.get("size") or 0),
            }
        )

    for part in payload.get("parts") or []:
        attachments.extend(_collect_attachments(part))

    return attachments


def clean_text(text: str) -> str:
    text = (text or "").replace("\r", "\n")
    lines = [line.strip() for line in text.split("\n")]
    non_empty = [line for line in lines if line]
    return "\n".join(non_empty).strip()


def extract_sender_email(from_header: str) -> str:
    _, email_address = parseaddr(from_header or "")
    return (email_address or "").strip().lower()


def extract_sender_domain(sender_email: str) -> str:
    sender = (sender_email or "").strip().lower()
    if "@" not in sender:
        return ""
    return sender.split("@", 1)[1].strip()


class GmailClient:
    def __init__(
        self,
        credentials_path: Path,
        token_path: Path,
        max_results: int = 20,
    ) -> None:
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.max_results = max_results
        self._service = self._build_service()

    def _build_service(self):
        creds: Optional[Credentials] = None

        if self.token_path.exists():
            creds = Credentials.from_authorized_user_file(str(self.token_path), SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not self.credentials_path.exists():
                    raise FileNotFoundError(
                        f"Gmail OAuth credentials not found at {self.credentials_path}. "
                        "Download credentials.json from Google Cloud and place it there."
                    )
                flow = InstalledAppFlow.from_client_secrets_file(str(self.credentials_path), SCOPES)
                creds = flow.run_local_server(port=0)

            self.token_path.write_text(creds.to_json(), encoding="utf-8")

        return build("gmail", "v1", credentials=creds, cache_discovery=False)

    def fetch_latest_messages(self, known_ids: set[str]) -> List[EmailMessage]:
        try:
            result = (
                self._service.users()
                .messages()
                .list(userId="me", labelIds=["INBOX"], maxResults=self.max_results)
                .execute()
            )
        except HttpError as exc:
            logger.error("Gmail API list call failed: %s", exc)
            raise

        messages = result.get("messages", [])
        if not messages:
            return []

        new_items: List[EmailMessage] = []
        for item in messages:
            email_id = str(item.get("id", ""))
            if not email_id or email_id in known_ids:
                continue

            try:
                raw_msg = (
                    self._service.users()
                    .messages()
                    .get(userId="me", id=email_id, format="full")
                    .execute()
                )
            except HttpError as exc:
                logger.warning("Failed to fetch Gmail message %s: %s", email_id, exc)
                continue

            payload = raw_msg.get("payload", {})
            headers = payload.get("headers", [])

            subject = clean_text(_extract_header(headers, "Subject"))
            body = clean_text(_extract_text_plain(payload))
            html_body = _extract_text_html(payload)
            sender = extract_sender_email(_extract_header(headers, "From"))
            sender_domain = extract_sender_domain(sender)
            reply_to = extract_sender_email(_extract_header(headers, "Reply-To"))
            return_path = extract_sender_email(_extract_header(headers, "Return-Path"))
            attachments = _collect_attachments(payload)

            new_items.append(
                EmailMessage(
                    email_id=email_id,
                    subject=subject,
                    body=body,
                    sender=sender,
                    sender_domain=sender_domain,
                    html_body=html_body,
                    attachments=attachments,
                    reply_to=reply_to,
                    return_path=return_path,
                )
            )

        return new_items
