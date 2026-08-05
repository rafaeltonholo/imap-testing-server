package mail.sandbox.dashboard.server.gate.dovecot

import kotlin.test.Test

class DovecotOperatorOwnedEvidenceLiveTest {
    private val audit = DovecotOperatorConfigTest()

    @Test
    fun pinnedEffectiveConfigKeepsPreinitSafeMasterDirectEligibilityMissingOrder() =
        audit.pinnedEffectiveConfigKeepsPreinitSafeMasterDirectEligibilityMissingOrder()

    @Test
    fun firstNonMasterPassdbCannotBeUnauthenticatedSkip() =
        audit.firstNonMasterPassdbCannotBeUnauthenticatedSkip()

    @Test
    fun imapsListenerMirrorsServiceUsersInsteadOfFallingBackToImageIdentities() =
        audit.imapsListenerMirrorsServiceUsersInsteadOfFallingBackToImageIdentities()

    @Test
    fun operatorEndpointRejectsThePlainAuthzidMasterFormByMechanism() =
        audit.operatorEndpointRejectsThePlainAuthzidMasterFormByMechanism()

    @Test
    fun pinnedOrdinaryEffectiveConfigRejectsEveryMasterPassdbMutation() =
        audit.pinnedOrdinaryEffectiveConfigRejectsEveryMasterPassdbMutation()

    @Test
    fun baseComposeKeepsOperatorBehindExplicitProfileAndScopedEvidenceSelectsIt() =
        audit.baseComposeKeepsOperatorBehindExplicitProfileAndScopedEvidenceSelectsIt()

    @Test
    fun resolvedBaseAndProofComposeKeepTheOperatorControlPlaneOnly() =
        audit.resolvedBaseAndProofComposeKeepTheOperatorControlPlaneOnly()

    @Test
    fun topologyAuditorRejectsEveryForbiddenBaseAndProofMutation() =
        audit.topologyAuditorRejectsEveryForbiddenBaseAndProofMutation()

    @Test
    fun resolvedComposeUsesOnlyReviewedOperatorMountsAndNeverMountsRawSecrets() =
        audit.resolvedComposeUsesOnlyReviewedOperatorMountsAndNeverMountsRawSecrets()

    @Test
    fun resolvedComposePinsBoundedQuietOperationalHealthcheck() =
        audit.resolvedComposePinsBoundedQuietOperationalHealthcheck()

    @Test
    fun proofOverrideExplicitlyClearsTheProductionOperatorProfile() =
        audit.proofOverrideExplicitlyClearsTheProductionOperatorProfile()

    @Test
    fun resolvedProofComposeUsesOnlyTheFixedIsolatedTopology() =
        audit.resolvedProofComposeUsesOnlyTheFixedIsolatedTopology()
}
