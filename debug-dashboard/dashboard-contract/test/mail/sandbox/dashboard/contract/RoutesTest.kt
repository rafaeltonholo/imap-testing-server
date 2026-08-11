package mail.sandbox.dashboard.contract

import kotlin.test.Test
import kotlin.test.assertEquals

class RoutesTest {
    @Test
    fun productRouteConstantsUseVersionedApiPaths() {
        assertEquals("/api/v1/accounts", Routes.ACCOUNTS)
        assertEquals("/api/v1/logs", Routes.LOGS)
        assertEquals("/api/v1/messages/generate", Routes.GENERATE_MESSAGE)
        assertEquals("/api/v1/authentication-probes", Routes.AUTHENTICATION_PROBES)
    }

    @Test
    fun accountRouteHelpersIncludeAddressAndProvider() {
        val account = "/api/v1/accounts/dev@local.test/providers/stalwart"

        assertEquals(account, Routes.account("dev@local.test", Provider.STALWART))
        assertEquals("$account/password", Routes.accountPassword("dev@local.test", Provider.STALWART))
        assertEquals(
            "$account/password/verify",
            Routes.accountPasswordVerification("dev@local.test", Provider.STALWART),
        )
        assertEquals("$account/folders", Routes.folders("dev@local.test", Provider.STALWART))
        assertEquals("$account/folders/archive", Routes.folder("dev@local.test", Provider.STALWART, "archive"))
        assertEquals("$account/messages", Routes.messages("dev@local.test", Provider.STALWART))
        assertEquals("$account/messages/message-1", Routes.message("dev@local.test", Provider.STALWART, "message-1"))
        assertEquals("$account/message-actions", Routes.messageActions("dev@local.test", Provider.STALWART))
        assertEquals("/api/v1/logs/accounts/dev@local.test/providers/stalwart", Routes.accountLogs("dev@local.test", Provider.STALWART))
    }

    @Test
    fun existingGateRoutesRemainStable() {
        assertEquals("/api/v1/gate/probe", Routes.GATE_PROBE)
        assertEquals("/api/v1/gate/events", Routes.GATE_EVENTS)
    }
}
