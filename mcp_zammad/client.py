"""Zammad API client wrapper for the MCP server."""

import logging
import os
from typing import Any
from urllib.parse import urlparse

import requests  # type: ignore[import-untyped]
from zammad_py import ZammadAPI
from zammad_py.exceptions import ConfigException

logger = logging.getLogger(__name__)


class ZammadClient:
    """Wrapper around zammad_py ZammadAPI with additional functionality."""

    def __init__(
        self,
        url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        http_token: str | None = None,
        oauth2_token: str | None = None,
        *,
        insecure: bool | None = None,
    ) -> None:
        """Initialize Zammad client with environment variables or provided credentials.

        Supports reading secrets from files using Docker secrets pattern:
        - ZAMMAD_HTTP_TOKEN_FILE: Path to file containing HTTP token
        - ZAMMAD_OAUTH2_TOKEN_FILE: Path to file containing OAuth2 token
        - ZAMMAD_PASSWORD_FILE: Path to file containing password

        Set insecure=True, or set ZAMMAD_INSECURE to 1/true/yes/on, only for
        trusted self-signed/internal certificate chains. Defaults to secure TLS
        verification.
        """
        self.url = url or os.getenv("ZAMMAD_URL")
        self.username = username or os.getenv("ZAMMAD_USERNAME")

        # Try to read secrets from files first (Docker secrets pattern)
        self.password = password or self._read_secret_file("ZAMMAD_PASSWORD_FILE") or os.getenv("ZAMMAD_PASSWORD")
        self.http_token = (
            http_token or self._read_secret_file("ZAMMAD_HTTP_TOKEN_FILE") or os.getenv("ZAMMAD_HTTP_TOKEN")
        )
        self.oauth2_token = (
            oauth2_token or self._read_secret_file("ZAMMAD_OAUTH2_TOKEN_FILE") or os.getenv("ZAMMAD_OAUTH2_TOKEN")
        )
        self.insecure = insecure if insecure is not None else ZammadClient._parse_bool_env("ZAMMAD_INSECURE")

        if not self.url:
            raise ConfigException("Zammad URL is required. Set ZAMMAD_URL environment variable.")

        # Validate URL format to prevent SSRF
        self._validate_url(self.url)

        if not any([self.http_token, self.oauth2_token, (self.username and self.password)]):
            # Check if user mistakenly used ZAMMAD_TOKEN
            if os.getenv("ZAMMAD_TOKEN"):
                raise ConfigException(
                    "Found ZAMMAD_TOKEN but this server expects ZAMMAD_HTTP_TOKEN. "
                    "Please rename your environment variable from ZAMMAD_TOKEN to ZAMMAD_HTTP_TOKEN."
                )
            raise ConfigException(
                "Authentication credentials required. Set either ZAMMAD_HTTP_TOKEN, "
                "ZAMMAD_OAUTH2_TOKEN, or both ZAMMAD_USERNAME and ZAMMAD_PASSWORD."
            )

        self.api = ZammadAPI(
            url=self.url,
            username=self.username,
            password=self.password,
            http_token=self.http_token,
            oauth2_token=self.oauth2_token,
        )
        if self.insecure:
            # Allow connecting to instances with self-signed/missing CA certs.
            session = getattr(self.api, "session", None)
            if session is None:
                connection = getattr(self.api, "_connection", None)
                session = getattr(connection, "session", None) if connection is not None else None
            if session is None:
                msg = (
                    "ZAMMAD_INSECURE is enabled but the installed zammad-py client does not expose a "
                    "requests session; TLS verification cannot be disabled."
                )
                raise ConfigException(msg)
            session.verify = False
            logger.warning(
                "TLS certificate verification is disabled (ZAMMAD_INSECURE=true). "
                "urllib3 may emit InsecureRequestWarning on requests; fix or trust the server certificate when possible."
            )

    def _validate_url(self, url: str) -> None:
        """Validate URL format to prevent SSRF attacks."""

        def _raise_config_error(message: str) -> None:
            """Helper to raise ConfigException."""
            raise ConfigException(message)

        try:
            parsed = urlparse(url)

            # Ensure URL has a scheme
            if not parsed.scheme:
                _raise_config_error("Zammad URL must include protocol (http:// or https://)")

            # Only allow http/https
            if parsed.scheme not in ["http", "https"]:
                _raise_config_error("Zammad URL must use http or https protocol")

            # Ensure URL has a hostname
            if not parsed.hostname:
                _raise_config_error("Zammad URL must include a valid hostname")

            # Block local/private networks (optional - adjust based on your security requirements)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]  # nosec B104
            if hostname in blocked_hosts:
                logger.warning(f"Zammad URL points to local host: {hostname}")

            # Check for private IP ranges (optional)
            if hostname.startswith(("10.", "192.168.", "172.")):
                logger.warning(f"Zammad URL points to private network: {hostname}")

        except Exception as e:
            raise ConfigException(f"Invalid Zammad URL format: {e}") from e

    def _read_secret_file(self, env_var: str) -> str | None:
        """Read secret from file path specified in environment variable.

        Args:
            env_var: Name of environment variable containing the file path

        Returns:
            Secret content from file or None if not found/readable
        """
        secret_file = os.getenv(env_var)
        if not secret_file:
            return None

        try:
            with open(secret_file) as f:
                return f.read().strip()
        except OSError:
            logger.warning(f"Failed to read secret for environment variable '{env_var}'.")
            return None

    @staticmethod
    def _parse_bool_env(env_var: str) -> bool:
        """Parse common truthy values from environment variables."""
        value = os.getenv(env_var, "").strip().lower()
        return value in {"1", "true", "yes", "on"}

    def search_tickets(
        self,
        query: str | None = None,
        state: str | None = None,
        priority: str | None = None,
        group: str | None = None,
        owner: str | None = None,
        customer: str | None = None,
        page: int = 1,
        per_page: int = 25,
    ) -> list[dict[str, Any]]:
        """Search tickets with various filters."""
        filters = {"page": page, "per_page": per_page, "expand": "true"}

        # Build search query
        search_parts = []
        if query:
            search_parts.append(query)
        if state:
            search_parts.append(f"state.name:{state}")
        if priority:
            search_parts.append(f"priority.name:{priority}")
        if group:
            search_parts.append(f"group.name:{group}")
        if owner:
            search_parts.append(f"owner.login:{owner}")
        if customer:
            search_parts.append(f"customer.email:{customer}")

        if search_parts:
            search_query = " AND ".join(search_parts)
            result = self.api.ticket.search(search_query, filters=filters)
        else:
            result = self.api.ticket.all(filters=filters)

        return list(result)

    def get_ticket(
        self, ticket_id: int, include_articles: bool = True, article_limit: int = 10, article_offset: int = 0
    ) -> dict[str, Any]:
        """Get a single ticket by ID with optional article pagination.

        The ticket is requested with ``expand=true`` so that ``group``, ``state``,
        ``priority``, ``owner`` and ``customer`` arrive as names instead of being
        absent. zammad_py's ``Ticket.find`` cannot pass query parameters, therefore
        the request goes through the authenticated session directly.
        """
        response = self.api.session.get(f"{self.url}/tickets/{ticket_id}", params={"expand": "true"})
        response.raise_for_status()
        ticket = dict(response.json())

        if include_articles:
            articles = self.api.ticket.articles(ticket_id)

            # Convert to list if needed
            articles_list = list(articles) if not isinstance(articles, list) else articles

            # Handle article pagination
            if article_limit == -1:  # -1 means get all articles
                ticket["articles"] = articles_list
            else:
                # Apply offset and limit
                start_idx = article_offset
                end_idx = start_idx + article_limit
                ticket["articles"] = articles_list[start_idx:end_idx]

        return dict(ticket)

    def create_ticket(
        self,
        title: str,
        group: str,
        customer: str,
        article_body: str,
        state: str = "new",
        priority: str = "2 normal",
        article_type: str = "note",
        article_internal: bool = False,
        owner: str | None = None,
        tags: list[str] | None = None,
        article_subject: str | None = None,
        article_content_type: str | None = None,
    ) -> dict[str, Any]:
        """Create a new ticket.

        ``owner`` is a login or e-mail address. ``tags`` are joined into the
        comma-separated string Zammad reads from ``params[:tags]`` on creation.
        Optional article fields are only sent when given so Zammad keeps its defaults.
        """
        article: dict[str, Any] = {
            "body": article_body,
            "type": article_type,
            "internal": article_internal,
        }
        if article_subject is not None:
            article["subject"] = article_subject
        if article_content_type is not None:
            article["content_type"] = article_content_type

        ticket_data: dict[str, Any] = {
            "title": title,
            "group": group,
            "customer": customer,
            "state": state,
            "priority": priority,
            "article": article,
        }
        if owner is not None:
            ticket_data["owner"] = owner
        if tags:
            ticket_data["tags"] = ",".join(tags)

        return dict(self.api.ticket.create(ticket_data))

    def update_ticket(
        self,
        ticket_id: int,
        title: str | None = None,
        state: str | None = None,
        priority: str | None = None,
        owner: str | None = None,
        group: str | None = None,
        time_unit: float | None = None,
    ) -> dict[str, Any]:
        """Update an existing ticket."""
        if time_unit is not None and time_unit <= 0:
            raise ValueError("time_unit must be greater than 0")

        update_data: dict[str, Any] = {}
        if title is not None:
            update_data["title"] = title
        if state is not None:
            update_data["state"] = state
        if priority is not None:
            update_data["priority"] = priority
        if owner is not None:
            update_data["owner"] = owner
        if group is not None:
            update_data["group"] = group
        if time_unit is not None:
            update_data["time_unit"] = time_unit

        return dict(self.api.ticket.update(ticket_id, update_data))

    def add_article(
        self,
        ticket_id: int,
        body: str,
        article_type: str = "note",
        internal: bool = False,
        sender: str = "Agent",
        time_unit: float | None = None,
        subject: str | None = None,
        to: str | None = None,
        cc: str | None = None,
        content_type: str | None = None,
        attachments: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Add an article (comment/note) to a ticket with optional attachments.

        Args:
            ticket_id: Ticket ID to add article to
            body: Article body content
            article_type: Article type (note, email, phone)
            internal: Whether the article is internal
            sender: Sender type (Agent, Customer, System)
            time_unit: Time spent for time accounting (unit defined in Zammad admin settings)
            subject: Optional email subject
            to: Optional email recipient
            cc: Optional email CC recipient(s)
            content_type: Optional content type (text/plain or text/html)
            attachments: Optional list of attachments with keys:
                - filename: str
                - data: str (base64-encoded content)
                - mime-type: str

        Returns:
            Created article data with attachment metadata
        """
        if time_unit is not None and time_unit <= 0:
            raise ValueError("time_unit must be greater than 0")

        article_data = {
            "ticket_id": ticket_id,
            "body": body,
            "type": article_type,
            "internal": internal,
            "sender": sender,
        }

        if time_unit is not None:
            article_data["time_unit"] = time_unit
        if subject is not None:
            article_data["subject"] = subject
        if to is not None:
            article_data["to"] = to
        if cc is not None:
            article_data["cc"] = cc
        if content_type is not None:
            article_data["content_type"] = content_type

        if attachments:
            article_data["attachments"] = attachments

        return dict(self.api.ticket_article.create(article_data))

    def delete_attachment(self, ticket_id: int, article_id: int, attachment_id: int) -> bool:
        """Delete an attachment from a ticket article.

        Args:
            ticket_id: Ticket ID
            article_id: Article ID
            attachment_id: Attachment ID to delete

        Returns:
            True if deletion succeeded

        Raises:
            Exception if deletion fails
        """
        result = self.api.ticket_article_attachment.destroy(attachment_id, article_id, ticket_id)
        # destroy() returns True on success, may return dict on error
        return bool(result)

    def get_user(self, user_id: int) -> dict[str, Any]:
        """Get user information by ID."""
        return dict(self.api.user.find(user_id))

    def search_users(
        self,
        query: str,
        page: int = 1,
        per_page: int = 25,
    ) -> list[dict[str, Any]]:
        """Search users."""
        filters = {"page": page, "per_page": per_page, "expand": "true"}
        result = self.api.user.search(query, filters=filters)
        return list(result)

    def create_user(
        self,
        email: str,
        firstname: str,
        lastname: str,
        login: str | None = None,
        phone: str | None = None,
        mobile: str | None = None,
        organization: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Create a new user in Zammad."""
        user_data: dict[str, Any] = {"email": email, "firstname": firstname, "lastname": lastname}
        if login:
            user_data["login"] = login
        if phone:
            user_data["phone"] = phone
        if mobile:
            user_data["mobile"] = mobile
        if organization:
            user_data["organization"] = organization
        if note:
            user_data["note"] = note
        return dict(self.api.user.create(user_data))

    def get_organization(self, org_id: int) -> dict[str, Any]:
        """Get organization information by ID."""
        return dict(self.api.organization.find(org_id))

    def search_organizations(
        self,
        query: str,
        page: int = 1,
        per_page: int = 25,
    ) -> list[dict[str, Any]]:
        """Search organizations."""
        filters = {"page": page, "per_page": per_page, "expand": "true"}
        result = self.api.organization.search(query, filters=filters)
        return list(result)

    def get_groups(self) -> list[dict[str, Any]]:
        """Get all groups.

        ``GET /groups`` is limited to ``admin.group`` before Zammad 7.0 and answers 403
        for plain agents. In that case the groups are read from the ticket creation
        form (``GET /ticket_create``), which every agent may call and which carries
        all groups as assets. The fallback is used for 403 only; other errors are raised.

        Returns:
            List of group objects with at least id, name and active fields.

        Raises:
            requests.HTTPError: If the API request fails for a reason other than 403.
        """
        response = self.api.session.get(f"{self.url}/groups", params={"per_page": self.FULL_LIST_PAGE_SIZE})
        if response.status_code != requests.codes.forbidden:
            response.raise_for_status()
            return list(response.json())

        logger.info("GET /groups answered 403, reading groups from the ticket creation form instead")
        form_response = self.api.session.get(f"{self.url}/ticket_create")
        form_response.raise_for_status()
        assets = form_response.json().get("assets", {})
        groups = list(assets.get("Group", {}).values())
        return sorted(groups, key=lambda group: int(group.get("id", 0)))

    # zammad_py's ``all()`` returns one page of ten items by default. States and
    # priorities are small, complete lists, so one page with a generous size fetches
    # all of them; an eleventh state must not vanish from the statistics.
    FULL_LIST_PAGE_SIZE = 500

    def get_ticket_states(self) -> list[dict[str, Any]]:
        """Get all ticket states."""
        result = self.api.ticket_state.all(filters={"per_page": self.FULL_LIST_PAGE_SIZE})
        return list(result)

    def get_ticket_priorities(self) -> list[dict[str, Any]]:
        """Get all ticket priorities."""
        result = self.api.ticket_priority.all(filters={"per_page": self.FULL_LIST_PAGE_SIZE})
        return list(result)

    def get_current_user(self) -> dict[str, Any]:
        """Get current authenticated user."""
        return dict(self.api.user.me())

    def get_ticket_tags(self, ticket_id: int) -> list[str]:
        """Get tags for a ticket."""
        tags = self.api.ticket.tags(ticket_id)
        return list(tags.get("tags", []))

    def add_ticket_tag(self, ticket_id: int, tag: str) -> dict[str, Any]:
        """Add a tag to a ticket.

        Returns:
            Dictionary with 'success' key (bool) and optional 'message' key.
            Format: {"success": True, "message": None}
        """
        result = self.api.ticket_tag.add(ticket_id, tag)
        # Zammad returns a boolean, convert to TagOperationResult format
        return {"success": result, "message": None}

    def remove_ticket_tag(self, ticket_id: int, tag: str) -> dict[str, Any]:
        """Remove a tag from a ticket.

        Returns:
            Dictionary with 'success' key (bool) and optional 'message' key.
            Format: {"success": True, "message": None}
        """
        result = self.api.ticket_tag.remove(ticket_id, tag)
        # Zammad returns a boolean, convert to TagOperationResult format
        return {"success": result, "message": None}

    def download_attachment(self, ticket_id: int, article_id: int, attachment_id: int) -> bytes:
        """Download an attachment from a ticket article."""
        result = self.api.ticket_article_attachment.download(attachment_id, article_id, ticket_id)
        return bytes(result)

    def get_article_attachments(self, _ticket_id: int, article_id: int) -> list[dict[str, Any]]:
        """Get list of attachments for a ticket article."""
        # Get the article with attachments
        article = self.api.ticket_article.find(article_id)
        attachments = article.get("attachments", [])
        return list(attachments)

    def list_tags(self) -> list[dict[str, Any]]:
        """Get all tags defined in the Zammad system.

        Uses direct HTTP call via zammad_py's internal session since
        the tag_list endpoint is not exposed by the library.

        Note:
            ``GET /tag_list`` requires admin.tag. Without it Zammad answers 403 and the
            tags are read from ``GET /tag_search`` instead, which agents may call. That
            endpoint knows no usage count, so ``count`` is ``None`` on the fallback path.

        Returns:
            List of tag objects with id, name, and count fields.

        Raises:
            requests.HTTPError: If the API request fails for a reason other than 403.
        """
        # Use zammad_py's internal session for authentication
        response = self.api.session.get(f"{self.url}/tag_list")
        if response.status_code != requests.codes.forbidden:
            response.raise_for_status()
            return list(response.json())

        logger.info("GET /tag_list answered 403, reading tags from tag_search instead")
        search_response = self.api.session.get(f"{self.url}/tag_search", params={"term": ""})
        search_response.raise_for_status()
        return [
            {"id": tag.get("id"), "name": tag.get("value"), "count": None}
            for tag in search_response.json()
            if tag.get("value")
        ]
