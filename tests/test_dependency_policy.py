from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLAN_ROOT = REPOSITORY_ROOT / "docs" / "superpowers" / "plans"

IMPLEMENTATION_PLAN = "2026-07-23-debug-dashboard-implementation.md"
FOUNDATION_PLAN = "2026-07-23-debug-dashboard-foundation.md"
ACCOUNT_PROVIDERS_PLAN = "2026-07-23-debug-dashboard-account-providers.md"
GATE_0B_PLAN = "2026-07-23-debug-dashboard-gate-0b-stalwart.md"
MAIL_PROVIDERS_PLAN = "2026-07-23-debug-dashboard-mail-providers.md"
MESSAGE_LAB_PLAN = "2026-07-23-debug-dashboard-message-lab-observability.md"

GATE_0B_SUPERSESSION_BANNER = (
    "> **Superseded dependency baseline:** This completed Gate 0B plan "
    "preserves the Stalwart v0.16.14 commands and evidence it actually "
    "proved. Active future work now targets Stalwart v0.16.15 under the "
    "2026-08-01 latest-coherent dependency plan; do not rewrite the "
    "historical steps below as v0.16.15 evidence."
)


class FuturePlanDependencyPolicyTest(unittest.TestCase):
    def plan_text(self, name: str) -> str:
        return (PLAN_ROOT / name).read_text(encoding="utf-8")

    def tech_stack(self, name: str) -> str:
        for line in self.plan_text(name).splitlines():
            if line.startswith("**Tech Stack:**"):
                return line
        self.fail(f"{name} must declare a Tech Stack summary")

    def test_implementation_plan_declares_selected_future_dependencies(self) -> None:
        text = self.plan_text(IMPLEMENTATION_PLAN)
        tech_stack = self.tech_stack(IMPLEMENTATION_PLAN)

        for selected in (
            "SQLite JDBC 3.53.2.1",
            "Jakarta Mail API 2.1.5",
            "Angus Mail 2.0.5",
            "jsoup 1.23.1",
            "Stalwart v0.16.15",
        ):
            with self.subTest(selected=selected):
                self.assertIn(selected, tech_stack)

        for declaration in (
            "- SQLite JDBC: `3.53.2.1`;",
            "- Angus Mail: `2.0.5` with Jakarta Mail API `2.1.5`;",
            "- jsoup: `1.23.1`.",
            (
                "| 0B | `2026-07-23-debug-dashboard-gate-0b-stalwart.md` | "
                "Stalwart v0.16.15 management plus Account-bound "
                "AppPassword/store/lifecycle, mail, submission, isolation, "
                "and deletion proof |"
            ),
        ):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, text)

        for superseded in (
            "- SQLite JDBC: `3.53.1.0`;",
            "- jsoup: `1.22.2`.",
            (
                "| 0B | `2026-07-23-debug-dashboard-gate-0b-stalwart.md` | "
                "Stalwart v0.16.14 management"
            ),
        ):
            with self.subTest(superseded=superseded):
                self.assertNotIn(superseded, text)

    def test_foundation_plan_declares_selected_sqlite_jdbc(self) -> None:
        text = self.plan_text(FOUNDATION_PLAN)

        self.assertIn("SQLite JDBC 3.53.2.1", self.tech_stack(FOUNDATION_PLAN))
        self.assertIn(
            "- [ ] Add `org.xerial:sqlite-jdbc:3.53.2.1`.",
            text,
        )
        self.assertNotIn("SQLite JDBC 3.53.1.0", self.tech_stack(FOUNDATION_PLAN))
        self.assertNotIn("org.xerial:sqlite-jdbc:3.53.1.0", text)

    def test_provider_plans_declare_selected_stalwart(self) -> None:
        for name in (
            ACCOUNT_PROVIDERS_PLAN,
            MAIL_PROVIDERS_PLAN,
            MESSAGE_LAB_PLAN,
        ):
            with self.subTest(plan=name):
                tech_stack = self.tech_stack(name)
                self.assertIn("Stalwart v0.16.15", tech_stack)
                self.assertNotIn("Stalwart v0.16.14", tech_stack)

    def test_mail_provider_plan_declares_selected_mail_and_html_libraries(self) -> None:
        text = self.plan_text(MAIL_PROVIDERS_PLAN)
        tech_stack = self.tech_stack(MAIL_PROVIDERS_PLAN)

        for selected in (
            "Jakarta Mail API 2.1.5",
            "Angus Mail 2.0.5",
        ):
            with self.subTest(selected=selected):
                self.assertIn(selected, tech_stack)
        self.assertIn(
            (
                "- [ ] Add compile dependencies "
                "`jakarta.mail:jakarta.mail-api:2.1.5` and runtime dependency "
                "`org.eclipse.angus:angus-mail:2.0.5`."
            ),
            text,
        )
        self.assertIn("- [ ] Add `org.jsoup:jsoup:1.23.1`.", text)
        self.assertNotIn("org.jsoup:jsoup:1.22.2", text)

    def test_message_lab_summary_declares_selected_shared_libraries(self) -> None:
        tech_stack = self.tech_stack(MESSAGE_LAB_PLAN)

        for selected in (
            "Jakarta Mail API 2.1.5",
            "Angus Mail 2.0.5",
            "SQLite JDBC 3.53.2.1",
        ):
            with self.subTest(selected=selected):
                self.assertIn(selected, tech_stack)

    def test_completed_gate_0b_keeps_historical_evidence_under_banner(self) -> None:
        text = self.plan_text(GATE_0B_PLAN)

        self.assertIn(GATE_0B_SUPERSESSION_BANNER, text)
        banner_index = text.index(GATE_0B_SUPERSESSION_BANNER)
        first_historical_index = text.index("Stalwart Community v0.16.14")
        self.assertLess(banner_index, first_historical_index)
        self.assertIn("stalwartlabs/stalwart:v0.16.14", text)
        self.assertIn("passes on Community v0.16.14", text)


if __name__ == "__main__":
    unittest.main()
