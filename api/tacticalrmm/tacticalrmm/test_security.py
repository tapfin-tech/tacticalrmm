"""Regression tests for the tapfin security/hardening branch."""

from unittest.mock import patch

import pyotp
from django.test import override_settings
from model_bakery import baker
from rest_framework.test import APIClient

from accounts.models import Role, User
from core.serializers import SECRET_MASK
from core.utils import _run_url_rest_action
from tacticalrmm.helpers import get_nats_admin_password
from tacticalrmm.security import (
    OutboundURLError,
    get_client_ip,
    validate_outbound_url,
    verify_totp,
)
from tacticalrmm.test import TacticalTestCase
from tacticalrmm.utils import get_db_value

LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


class TestServerSide2FA(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.client = APIClient()
        self.bob = User(username="bob")
        self.bob.set_password("Str0ng-Passw0rd!x")
        self.bob.save()

    def _checkcreds_token(self) -> str:
        r = self.client.post(
            "/v2/checkcreds/",
            {"username": "bob", "password": "Str0ng-Passw0rd!x"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.data["totp"])
        return r.data["token"]

    def test_token_without_totp_only_reaches_enrolment(self):
        token = self._checkcreds_token()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

        # any normal endpoint is refused
        r = self.client.get("/agents/")
        self.assertEqual(r.status_code, 401)
        r = self.client.get("/core/settings/")
        self.assertEqual(r.status_code, 401)

        # the enrolment endpoint works
        r = self.client.post("/accounts/users/setup_totp/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data["totp_key"])

    def test_token_after_totp_enrolled_works(self):
        token = self._checkcreds_token()
        self.bob.totp_key = pyotp.random_base32()
        self.bob.is_superuser = True
        self.bob.save()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        r = self.client.get("/core/settings/")
        self.assertEqual(r.status_code, 200)

    @override_settings(TRMM_ENFORCE_2FA=False)
    def test_enforcement_can_be_turned_off(self):
        token = self._checkcreds_token()
        self.bob.is_superuser = True
        self.bob.save()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        r = self.client.get("/core/settings/")
        self.assertEqual(r.status_code, 200)


@override_settings(CACHES=LOCMEM_CACHE, TRMM_TOTP_VALID_WINDOW=1)
class TestTOTP(TacticalTestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="totp", password="x")
        self.user.totp_key = pyotp.random_base32()
        self.user.save()

    def test_code_is_single_use(self):
        code = pyotp.TOTP(self.user.totp_key).now()
        self.assertTrue(verify_totp(self.user, code))
        self.assertFalse(verify_totp(self.user, code))

    def test_wide_window_rejected(self):
        import time

        old = pyotp.TOTP(self.user.totp_key).at(time.time() - 30 * 5)
        self.assertFalse(verify_totp(self.user, old))

    def test_no_key_or_code(self):
        self.user.totp_key = ""
        self.assertFalse(verify_totp(self.user, "123456"))


class TestClientIP(TacticalTestCase):
    def test_spoofed_xff_ignored(self):
        meta = {
            "REMOTE_ADDR": "10.0.0.5",
            "HTTP_X_FORWARDED_FOR": "1.1.1.1, 203.0.113.9",
        }
        with self.settings(TRMM_NUM_PROXIES=1):
            self.assertEqual(get_client_ip(meta), "203.0.113.9")
        with self.settings(TRMM_NUM_PROXIES=2):
            self.assertEqual(get_client_ip(meta), "1.1.1.1")
        with self.settings(TRMM_NUM_PROXIES=0):
            self.assertEqual(get_client_ip(meta), "10.0.0.5")

    def test_no_xff(self):
        with self.settings(TRMM_NUM_PROXIES=1):
            self.assertEqual(get_client_ip({"REMOTE_ADDR": "10.0.0.5"}), "10.0.0.5")


class TestReportingDisabled(TacticalTestCase):
    """CI keeps reporting on so upstream's EE tests run; production defaults off."""

    def _reporting_routed(self) -> bool:
        import importlib

        import tacticalrmm.urls as urls

        importlib.reload(urls)
        return any(str(p.pattern) == "reporting/" for p in urls.urlpatterns)

    def tearDown(self):
        import importlib

        import tacticalrmm.urls as urls

        importlib.reload(urls)

    @override_settings(TRMM_DISABLE_REPORTING=True)
    def test_disabled_removes_routes(self):
        self.assertFalse(self._reporting_routed())

    @override_settings(TRMM_DISABLE_REPORTING=False)
    def test_enabled_adds_routes(self):
        self.assertTrue(self._reporting_routed())


class TestNatsPassword(TacticalTestCase):
    @override_settings(NATS_ADMIN_PASSWORD="separate-nats-secret")
    def test_separate_password(self):
        self.assertEqual(get_nats_admin_password(), "separate-nats-secret")

    @override_settings(NATS_ADMIN_PASSWORD="")
    def test_fallback(self):
        from django.conf import settings

        self.assertEqual(get_nats_admin_password(), settings.SECRET_KEY)


class TestCoreSettingsSecrets(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        from core.models import CoreSettings

        cs = CoreSettings.objects.first()
        cs.smtp_host_password = "smtp-secret"
        cs.mesh_token = "mesh-secret"
        cs.save()
        self.client = APIClient()

    def _user_with(self, **perms) -> User:
        role = baker.make("accounts.Role", **perms)
        user = baker.make("accounts.User", role=role)
        self.client.force_authenticate(user=user)
        return user

    def test_view_only_user_gets_masked_secrets(self):
        self._user_with(can_view_core_settings=True)
        r = self.client.get("/core/settings/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["smtp_host_password"], SECRET_MASK)
        self.assertEqual(r.data["mesh_token"], SECRET_MASK)

    def test_editor_gets_values(self):
        self._user_with(can_view_core_settings=True, can_edit_core_settings=True)
        r = self.client.get("/core/settings/")
        self.assertEqual(r.data["smtp_host_password"], "smtp-secret")

    def test_masked_value_does_not_overwrite(self):
        from core.models import CoreSettings

        self._user_with(can_view_core_settings=True, can_edit_core_settings=True)
        r = self.client.put(
            "/core/settings/", {"smtp_host_password": SECRET_MASK}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(CoreSettings.objects.first().smtp_host_password, "smtp-secret")

    def test_audit_serializer_masks(self):
        from core.models import CoreSettings

        data = CoreSettings.serialize(CoreSettings.objects.first())
        self.assertEqual(data["smtp_host_password"], SECRET_MASK)


class TestPrivilegeEscalation(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.client = APIClient()
        self.super_role = baker.make("accounts.Role", is_superuser=True)
        self.manager_role = baker.make(
            "accounts.Role",
            can_list_accounts=True,
            can_manage_accounts=True,
            can_list_roles=True,
            can_manage_roles=True,
        )
        self.manager = baker.make("accounts.User", role=self.manager_role)
        self.admin = User.objects.create_superuser(
            "root", "root@example.com", "Str0ng-Passw0rd!x"
        )
        self.client.force_authenticate(user=self.manager)

    def test_manager_cannot_reset_superuser_password(self):
        r = self.client.post(
            "/accounts/users/reset/",
            {"id": self.admin.pk, "password": "An0ther-Str0ng!pw"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_manager_cannot_reset_superuser_2fa(self):
        r = self.client.put(
            "/accounts/users/reset_totp/", {"id": self.admin.pk}, format="json"
        )
        self.assertEqual(r.status_code, 400)

    def test_manager_cannot_grant_superuser_role(self):
        r = self.client.put(
            f"/accounts/{self.manager.pk}/users/",
            {"role": self.super_role.pk},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.manager.refresh_from_db()
        self.assertEqual(self.manager.role, self.manager_role)

    def test_manager_cannot_create_superuser_role(self):
        r = self.client.post(
            "/accounts/roles/", {"name": "evil", "is_superuser": True}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertFalse(Role.objects.filter(name="evil").exists())

    def test_manager_can_still_manage_normal_users(self):
        other = baker.make("accounts.User")
        r = self.client.post(
            "/accounts/users/reset/",
            {"id": other.pk, "password": "An0ther-Str0ng!pw"},
            format="json",
        )
        self.assertEqual(r.status_code, 200)


class TestPasswordPolicy(TacticalTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_weak_password_rejected_on_create(self):
        r = self.client.post(
            "/accounts/users/",
            {"username": "weak", "password": "password", "email": "w@example.com"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertFalse(User.objects.filter(username="weak").exists())

    def test_weak_password_rejected_on_self_reset(self):
        r = self.client.put("/accounts/resetpw/", {"password": "12345678"})
        self.assertEqual(r.status_code, 400)


class TestOutboundURL(TacticalTestCase):
    def test_blocks_internal(self):
        for url in (
            "http://127.0.0.1/",
            "http://localhost:6379/",
            "http://10.1.2.3/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "file:///etc/passwd",
            "gopher://example.com/",
        ):
            with self.assertRaises(OutboundURLError, msg=url):
                validate_outbound_url(url)

    @patch("socket.getaddrinfo")
    def test_allows_public(self, mock_dns):
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        validate_outbound_url("https://example.com/hook")

    @override_settings(TRMM_URL_ACTION_ALLOWED_HOSTS=["n8n.internal"])
    def test_allow_list(self):
        validate_outbound_url("http://n8n.internal/hook")

    @override_settings(TRMM_URL_ACTION_ALLOW_PRIVATE=True)
    def test_allow_private_switch(self):
        validate_outbound_url("http://127.0.0.1/")

    def test_url_action_refuses_internal(self):
        with self.assertRaises(OutboundURLError):
            _run_url_rest_action(
                url="http://127.0.0.1:5432/", method="get", body="", headers="{}"
            )


class TestDbValueSecrets(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_agent_token_not_resolvable(self):
        agent = baker.make_recipe("agents.agent")
        self.setup_agent_auth(agent)
        agent.refresh_from_db()
        self.assertIsNone(
            get_db_value(string="agent.user.auth_token.key", instance=agent)
        )
        self.assertIsNone(get_db_value(string="agent._state", instance=agent))
        # normal lookups still work
        self.assertEqual(
            get_db_value(string="agent.hostname", instance=agent), agent.hostname
        )


class TestAgentScopes(TacticalTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.client = APIClient()

    def test_agent_cannot_report_other_agents_check(self):
        agent1 = baker.make_recipe("agents.agent")
        agent2 = baker.make_recipe("agents.agent")
        check = baker.make_recipe("checks.ping_check", agent=agent2)
        self.setup_agent_auth(agent1)
        user = User.objects.get(username=agent1.agent_id)
        agent1.user = user
        user.agent = agent1
        user.save()
        self.client.force_authenticate(user=user)
        r = self.client.patch(
            "/api/v3/checkrunner/",
            {"id": check.pk, "agent_id": agent1.agent_id, "status": "failing"},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_low_priv_user_cannot_enroll_agent(self):
        site = baker.make("clients.Site")
        role = baker.make("accounts.Role")  # no permissions
        user = baker.make("accounts.User", role=role)
        self.client.force_authenticate(user=user)
        r = self.client.post(
            "/api/v3/newagent/",
            {
                "agent_id": "a" * 40,
                "hostname": "x",
                "site": site.pk,
                "monitoring_type": "server",
                "description": "",
                "mesh_node_id": "",
                "goarch": "amd64",
                "plat": "windows",
            },
            format="json",
        )
        self.assertEqual(r.status_code, 403)
