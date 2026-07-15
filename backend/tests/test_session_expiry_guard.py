import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
FRONTEND = ROOT / "frontend" / "src"


class SessionExpiryGuardRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = (FRONTEND / "api" / "client.ts").read_text(encoding="utf-8")
        cls.provider = (FRONTEND / "auth" / "AuthProvider.tsx").read_text(encoding="utf-8")
        cls.guard = (FRONTEND / "auth" / "SessionExpiryGuard.tsx").read_text(encoding="utf-8")
        cls.protected = (FRONTEND / "auth" / "ProtectedRoute.tsx").read_text(encoding="utf-8")
        cls.modal = (FRONTEND / "pages" / "access" / "components" / "SessionExpiryModal.tsx").read_text(encoding="utf-8")

    def test_bootstrap_and_auth_failures_are_not_expiry_events(self):
        for endpoint in ("/auth/login", "/auth/mfa/verify-login", "/auth/logout", "/auth/csrf"):
            self.assertIn(endpoint, self.client)
        self.assertIn("isAuthenticationLifecycleRequest", self.client)
        lifecycle_body = self.client.split("function isAuthenticationLifecycleRequest", 1)[1].split("apiClient.interceptors.request", 1)[0]
        self.assertNotIn("/auth/me", lifecycle_body)

    def test_genuine_unauthorized_uses_bounded_provider_callback(self):
        self.assertIn("registerUnauthorizedHandler", self.client)
        self.assertIn("unauthorizedHandler?.({ requestUrl })", self.client)
        self.assertIn("clearCsrfToken();", self.client)
        self.assertIn("hasEstablishedSession", self.provider)

    def test_initial_anonymous_bootstrap_does_not_establish_expiry(self):
        self.assertIn("apiClient.get<AuthUser>('/auth/me')", self.provider)
        self.assertIn("setUser(null);", self.provider)
        self.assertNotIn("setSessionExpired(true)", self.provider.split("const reload", 1)[1].split("useEffect", 1)[0])

    def test_duplicate_unauthorized_responses_are_suppressed(self):
        self.assertIn("sessionExpiryTriggered", self.provider)
        self.assertIn("if (!hasEstablishedSession.current || sessionExpiryTriggered.current) return;", self.provider)

    def test_public_routes_never_render_the_modal(self):
        for path in ("'/'", "/login", "/mfa-challenge", "/forbidden"):
            self.assertIn(path, self.guard)
        self.assertNotIn("/change-password", self.guard)
        self.assertIn("!publicPath", self.guard)

    def test_protected_route_unmounts_content_after_expiry(self):
        self.assertIn("if (sessionExpired) return <div", self.protected)
        self.assertNotIn("if (sessionExpired) return <Outlet />;", self.protected)
        self.assertIn("<Navigate to=\"/login\"", self.protected)

    def test_return_to_login_clears_expired_state_before_navigation(self):
        self.assertIn("clearExpiredSession();", self.modal)
        self.assertIn("navigate('/login', { replace: true })", self.modal)
        clear_body = self.provider.split("const clearExpiredSession", 1)[1].split("const reload", 1)[0]
        for reset in ("hasEstablishedSession.current = false", "sessionExpiryTriggered.current = false", "setUser(null)", "setSessionExpired(false)", "clearCsrfToken()"):
            self.assertIn(reset, clear_body)

    def test_login_and_logout_clear_stale_expiry_state(self):
        self.assertGreaterEqual(self.provider.count("setSessionExpired(false)"), 3)
        self.assertIn("hasEstablishedSession.current = false;", self.provider)


if __name__ == "__main__":
    unittest.main()
