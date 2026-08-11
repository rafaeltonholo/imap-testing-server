package mail.sandbox.dashboard.web

import kotlin.test.Test
import kotlin.test.assertEquals
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.ChangePasswordRequest
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CredentialUpdateResponse
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider

class DashboardApiContractTest {
    @Test
    @Suppress("UNUSED_VARIABLE")
    fun passwordChangeUsesTheItemizedCredentialUpdateContract() {
        val changePassword:
            suspend DashboardApi.(AccountTarget, ChangePasswordRequest) -> CredentialUpdateResponse =
            DashboardApi::changePassword
        val adoptPassword:
            suspend DashboardApi.(AccountTarget, AdoptPasswordRequest) -> CredentialUpdateResponse =
            DashboardApi::adoptPassword
        val probeAuthentication:
            suspend DashboardApi.(AuthenticationProbeRequest) -> AuthenticationProbeResponse =
            DashboardApi::probeAuthentication
        val response = CredentialUpdateResponse(
            address = "dev@local.test",
            provider = Provider.DOVECOT,
            readiness = CredentialReadiness.READY,
            operation = OperationResponse(success = true, message = "verified"),
        )

        assertEquals("verified", response.operation.message)
    }
}
