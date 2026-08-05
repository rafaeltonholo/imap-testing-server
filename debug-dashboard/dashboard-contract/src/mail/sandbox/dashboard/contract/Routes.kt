package mail.sandbox.dashboard.contract

object Routes {
    const val ACCOUNTS = "/api/v1/accounts"
    const val LOGS = "/api/v1/logs"
    const val GENERATE_MESSAGE = "/api/v1/messages/generate"

    const val GATE_PROBE = "/api/v1/gate/probe"
    const val GATE_EVENTS = "/api/v1/gate/events"

    fun account(address: String, provider: Provider): String =
        "$ACCOUNTS/$address/providers/${provider.pathSegment()}"

    fun accountPassword(address: String, provider: Provider): String =
        "${account(address, provider)}/password"

    fun folders(address: String, provider: Provider): String =
        "${account(address, provider)}/folders"

    fun folder(address: String, provider: Provider, folderId: String): String =
        "${folders(address, provider)}/$folderId"

    fun messages(address: String, provider: Provider): String =
        "${account(address, provider)}/messages"

    fun message(address: String, provider: Provider, messageId: String): String =
        "${messages(address, provider)}/$messageId"

    fun messageActions(address: String, provider: Provider): String =
        "${account(address, provider)}/message-actions"

    fun accountLogs(address: String, provider: Provider): String =
        "$LOGS/accounts/$address/providers/${provider.pathSegment()}"

    private fun Provider.pathSegment(): String = name.lowercase()
}
