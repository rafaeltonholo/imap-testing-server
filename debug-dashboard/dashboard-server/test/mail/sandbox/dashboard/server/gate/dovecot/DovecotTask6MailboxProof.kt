package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.charset.StandardCharsets

internal fun seedAndProbeTask6IsolationMailbox(
    leaseRegistry: DovecotOperatorApplicationLeaseRegistry,
    transportFactory: DovecotOperatorTransportFactory,
    target: DovecotOperatorTarget,
    credentialSupplier: () -> DovecotOperatorCredential,
): DovecotOperatorProbeResult {
    val message = deterministicTask6IsolationMessage(target)
    var seedCredential: DovecotOperatorCredential? = null
    try {
        seedCredential = credentialSupplier()
        HeldDovecotOperatorImapSession.openAndSeedLeased(
            leaseRegistry = leaseRegistry,
            transportFactory = transportFactory,
            target = target,
            credential = seedCredential,
            message = message,
        ).use { }
    } finally {
        seedCredential?.close()
        message.fill(0)
    }
    return DovecotOperatorProbe(
        transportFactory = transportFactory,
        requireMailboxRead = true,
    ).probe(target, credentialSupplier())
}

private fun deterministicTask6IsolationMessage(
    target: DovecotOperatorTarget,
): ByteArray =
    (
        "From: dashboard-isolation@local.test\r\n" +
            "To: ${target.address}\r\n" +
            "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
            "Subject: Dovecot Task 6 isolation proof\r\n" +
            "Message-ID: <task6-isolation-read-proof.${target.address}>\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=UTF-8\r\n" +
            "\r\n" +
            "Deterministic Dovecot Task 6 isolation mailbox proof.\r\n"
        ).toByteArray(StandardCharsets.US_ASCII)
