/*
THESIS: Mail state and the evidence it caused share one operating surface, refusing a generic admin card grid.
OWN-WORLD: Recorder-paper work zones bolt into a graphite shell; cyan and amber edge channels register provider ownership.
STORY: Select an account channel, create or mutate mailbox state, then read its provider result and correlated logs in place.
FIRST VIEWPORT: A compact runtime strip and product rail lead into accounts, folders/messages, reader, and trace in a 62/38 evidence split.
FORM: Flat keylines, low radii, dense workhorse type, technical monospace only for evidence, and structural narrow-screen stages.
*/
package mail.sandbox.dashboard.web

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Shapes
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.js.ExperimentalWasmJsInterop
import kotlin.js.JsString
import kotlin.js.unsafeCast
import kotlinx.browser.window
import kotlinx.coroutines.await
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.GateEvent
import mail.sandbox.dashboard.contract.GateProbe
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.contract.ProviderStatus
import mail.sandbox.dashboard.contract.Routes
import mail.sandbox.dashboard.contract.gate.GateAction
import mail.sandbox.dashboard.contract.gate.GateRoute
import mail.sandbox.dashboard.contract.gate.GateState
import mail.sandbox.dashboard.contract.gate.reduceGateState
import mail.sandbox.dashboard.web.generated.resources.Res
import org.w3c.dom.EventSource
import org.w3c.dom.MessageEvent
import org.w3c.dom.events.Event
import org.w3c.fetch.Response

private val InstrumentGraphite = Color(0xFF17242A)
private val DeepGraphite = Color(0xFF101A1E)
private val RecorderPaper = Color(0xFFF4F2E8)
private val PanelFog = Color(0xFFE8E7DE)
private val PanelFogDark = Color(0xFFD9D9D0)
private val SilkscreenGray = Color(0xFF526064)
private val ShellLabel = Color(0xFFCAD2D1)
private val DovecotCyan = Color(0xFF0B8F9C)
private val DovecotWash = Color(0xFFD8EEF0)
private val StalwartAmber = Color(0xFFE58A1F)
private val StalwartWash = Color(0xFFF7E6CB)
private val RecorderCursorRed = Color(0xFFC7473A)
private val ErrorWash = Color(0xFFF2D9D4)
private val VerifiedGreen = Color(0xFF2F7E62)
private val GreenWash = Color(0xFFD9E8E1)

private val DashboardColorScheme = lightColorScheme(
    primary = InstrumentGraphite,
    onPrimary = RecorderPaper,
    primaryContainer = PanelFogDark,
    onPrimaryContainer = InstrumentGraphite,
    secondary = DovecotCyan,
    onSecondary = Color.White,
    tertiary = StalwartAmber,
    onTertiary = InstrumentGraphite,
    background = InstrumentGraphite,
    onBackground = RecorderPaper,
    surface = RecorderPaper,
    onSurface = InstrumentGraphite,
    surfaceVariant = PanelFog,
    onSurfaceVariant = SilkscreenGray,
    error = RecorderCursorRed,
    onError = Color.White,
    errorContainer = ErrorWash,
    onErrorContainer = InstrumentGraphite,
    outline = SilkscreenGray,
)

private val DashboardShapes = Shapes(
    extraSmall = RoundedCornerShape(1.dp),
    small = RoundedCornerShape(2.dp),
    medium = RoundedCornerShape(3.dp),
    large = RoundedCornerShape(4.dp),
    extraLarge = RoundedCornerShape(4.dp),
)

private enum class NarrowStage(val label: String) {
    Accounts("Accounts"),
    Mailbox("Mailbox"),
    Message("Message"),
    Authentication("Authentication"),
    Trace("Trace"),
}

private enum class TraceMode(val label: String) {
    Account("Account trace"),
    Server("Server logs"),
}

private enum class PasswordActionMode(val label: String) {
    VERIFY("Verify existing password"),
    RESET("Reset password"),
}

private enum class ProbeCredentialSource(val label: String) {
    REMEMBERED("Remembered credential"),
    OVERRIDE("Request override"),
}

@OptIn(ExperimentalWasmJsInterop::class)
@Composable
internal fun DashboardApp(modifier: Modifier = Modifier) {
    val controller = remember { DashboardController() }
    val initialRoute = GateRoute.fromPath(window.location.pathname) ?: GateRoute.Overview
    var gateState by remember { mutableStateOf(GateState(route = initialRoute)) }
    var resourceMarker by remember { mutableStateOf("GATE_RESOURCE: loading") }
    val dispatch: (GateAction) -> Unit = { action ->
        gateState = reduceGateState(gateState, action)
    }

    LaunchedEffect(Unit) {
        resourceMarker = Res.readBytes("files/gate-proof.txt").decodeToString().trim()
    }
    LaunchedEffect(Unit) {
        controller.initialize()
    }
    LaunchedEffect(Unit) {
        dispatch(GateAction.ApiProbeStarted)
        runCatching {
            val response: Response = window.fetch(Routes.GATE_PROBE).await()
            require(response.ok) { "HTTP ${response.status}" }
            val body: JsString = response.text().await()
            Json.decodeFromString<GateProbe>(body.toString())
        }.onSuccess { probe ->
            dispatch(GateAction.ApiProbeSucceeded(probe.message))
        }.onFailure { failure ->
            dispatch(GateAction.ApiProbeFailed(failure.message ?: "probe failed"))
        }
    }

    DisposableEffect(Unit) {
        val popStateListener: (Event) -> Unit = {
            dispatch(GateAction.RouteSelected(window.location.pathname))
        }
        window.addEventListener("popstate", popStateListener)
        onDispose { window.removeEventListener("popstate", popStateListener) }
    }

    DisposableEffect(Unit) {
        val eventSource = EventSource(Routes.GATE_EVENTS)
        val resyncListener: (Event) -> Unit = { rawEvent ->
            val event = rawEvent.unsafeCast<MessageEvent>()
            val gateEvent = decodeGateEvent(event)
            if (gateEvent?.kind == "resync") {
                dispatch(GateAction.SseResyncStarted)
                eventSource.close()
                dispatch(GateAction.SseDisconnected)
            } else {
                dispatch(GateAction.SseSequenceReceived(0L))
            }
        }
        eventSource.onopen = { dispatch(GateAction.SseConnected) }
        eventSource.onmessage = { event ->
            val gateEvent = decodeGateEvent(event)
            if (gateEvent?.kind == "sequence" && gateEvent.id == gateEvent.payload.sequence) {
                dispatch(GateAction.SseSequenceReceived(gateEvent.payload.sequence))
            } else {
                dispatch(GateAction.SseSequenceReceived(0L))
            }
        }
        eventSource.onerror = {
            if (eventSource.readyState == EventSource.CONNECTING) {
                dispatch(GateAction.SseReconnectScheduled)
            }
        }
        eventSource.addEventListener("resync", resyncListener)
        onDispose {
            eventSource.removeEventListener("resync", resyncListener)
            eventSource.onopen = null
            eventSource.onmessage = null
            eventSource.onerror = null
            eventSource.close()
        }
    }

    MaterialTheme(
        colorScheme = DashboardColorScheme,
        shapes = DashboardShapes,
    ) {
        DashboardSurface(
            controller = controller,
            gateState = gateState,
            resourceMarker = resourceMarker,
            onGateAction = dispatch,
            onRouteSelected = { route ->
                if (route != gateState.route) {
                    window.history.pushState(null, "", route.path)
                    dispatch(GateAction.RouteSelected(route.path))
                }
            },
            modifier = modifier,
        )
    }
}

@OptIn(ExperimentalWasmJsInterop::class)
private fun decodeGateEvent(event: MessageEvent): GateEvent? = runCatching {
    val data = event.data?.unsafeCast<JsString>()?.toString() ?: return@runCatching null
    Json.decodeFromString<GateEvent>(data)
}.getOrNull()

@Composable
private fun DashboardSurface(
    controller: DashboardController,
    gateState: GateState,
    resourceMarker: String,
    onGateAction: (GateAction) -> Unit,
    onRouteSelected: (GateRoute) -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    var narrowStage by remember { mutableStateOf(NarrowStage.Accounts) }
    var traceMode by remember { mutableStateOf(TraceMode.Account) }
    var createAccountOpen by remember { mutableStateOf(false) }
    var passwordMode by remember { mutableStateOf<PasswordActionMode?>(null) }
    var accountDeleteOpen by remember { mutableStateOf(false) }
    var createFolderOpen by remember { mutableStateOf(false) }
    var folderPendingDelete by remember { mutableStateOf<FolderInfo?>(null) }
    var generateOpen by remember { mutableStateOf(false) }
    var messageDeleteOpen by remember { mutableStateOf(false) }
    var destinationFolderId by remember { mutableStateOf<String?>(null) }

    BoxWithConstraints(
        modifier = modifier
            .fillMaxSize()
            .background(InstrumentGraphite),
    ) {
        val wide = maxWidth >= 1040.dp
        Column(Modifier.fillMaxSize()) {
            RuntimeStrip(
                state = gateState,
                resourceMarker = resourceMarker,
                onAction = onGateAction,
                onRouteSelected = onRouteSelected,
            )
            ProductHeader(
                controller = controller,
                onAddAccount = { createAccountOpen = true },
                onGenerate = { generateOpen = true },
                onRefresh = { scope.launch { controller.refreshAccounts() } },
            )
            ProviderStatusRail(
                statuses = controller.providerStatuses,
                compact = !wide,
            )

            if (wide) {
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(start = 12.dp, end = 12.dp, bottom = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    AccountsPane(
                        controller = controller,
                        onSelect = { target -> scope.launch { controller.selectAccount(target) } },
                        onAdd = { createAccountOpen = true },
                        modifier = Modifier
                            .width(252.dp)
                            .fillMaxHeight(),
                    )
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight(),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        AccountHeader(
                            controller = controller,
                            onVerifyPassword = { passwordMode = PasswordActionMode.VERIFY },
                            onResetPassword = { passwordMode = PasswordActionMode.RESET },
                            onDelete = { accountDeleteOpen = true },
                            onRefresh = { scope.launch { controller.refreshAccounts() } },
                        )
                        Row(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            MailboxPane(
                                controller = controller,
                                compact = false,
                                onCreateFolder = { createFolderOpen = true },
                                onDeleteFolder = { folderPendingDelete = it },
                                onSelectFolder = { folderId ->
                                    scope.launch { controller.selectFolder(folderId) }
                                },
                                onSelectMessage = { summary ->
                                    scope.launch { controller.selectMessage(summary) }
                                },
                                modifier = Modifier
                                    .weight(0.62f)
                                    .fillMaxHeight(),
                            )
                            Column(
                                modifier = Modifier
                                    .weight(0.38f)
                                    .fillMaxHeight(),
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                MessageReaderPane(
                                    controller = controller,
                                    destinationFolderId = destinationFolderId,
                                    onDestinationChanged = { destinationFolderId = it },
                                    onAction = { action, destination ->
                                        scope.launch {
                                            controller.mutateSelectedMessage(action, destination)
                                        }
                                    },
                                    onDelete = { messageDeleteOpen = true },
                                    modifier = Modifier
                                        .weight(0.40f)
                                        .fillMaxWidth(),
                                )
                                AuthenticationProbePane(
                                    controller = controller,
                                    modifier = Modifier
                                        .weight(0.26f)
                                        .fillMaxWidth(),
                                )
                                TracePane(
                                    controller = controller,
                                    mode = traceMode,
                                    onModeChanged = { traceMode = it },
                                    onRefreshAccount = {
                                        scope.launch { controller.refreshAccountLogs() }
                                    },
                                    onRefreshServer = { service ->
                                        scope.launch { controller.refreshGlobalLogs(service) }
                                    },
                                    modifier = Modifier
                                        .weight(0.34f)
                                        .fillMaxWidth(),
                                )
                            }
                        }
                    }
                }
            } else {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(start = 8.dp, end = 8.dp, bottom = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    CompactAccountSummary(controller.selectedAccount)
                    NarrowStageRail(
                        stage = narrowStage,
                        onStageSelected = { narrowStage = it },
                    )
                    when (narrowStage) {
                        NarrowStage.Accounts -> AccountsPane(
                            controller = controller,
                            onSelect = { target ->
                                scope.launch {
                                    controller.selectAccount(target)
                                    narrowStage = NarrowStage.Mailbox
                                }
                            },
                            onAdd = { createAccountOpen = true },
                            modifier = Modifier.fillMaxSize(),
                        )

                        NarrowStage.Mailbox -> Column(
                            modifier = Modifier.fillMaxSize(),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            AccountHeader(
                                controller = controller,
                                onVerifyPassword = { passwordMode = PasswordActionMode.VERIFY },
                                onResetPassword = { passwordMode = PasswordActionMode.RESET },
                                onDelete = { accountDeleteOpen = true },
                                onRefresh = { scope.launch { controller.refreshAccounts() } },
                            )
                            MailboxPane(
                                controller = controller,
                                compact = true,
                                onCreateFolder = { createFolderOpen = true },
                                onDeleteFolder = { folderPendingDelete = it },
                                onSelectFolder = { folderId ->
                                    scope.launch { controller.selectFolder(folderId) }
                                },
                                onSelectMessage = { summary ->
                                    scope.launch {
                                        controller.selectMessage(summary)
                                        narrowStage = NarrowStage.Message
                                    }
                                },
                                modifier = Modifier
                                    .weight(1f)
                                    .fillMaxWidth(),
                            )
                        }

                        NarrowStage.Message -> MessageReaderPane(
                            controller = controller,
                            destinationFolderId = destinationFolderId,
                            onDestinationChanged = { destinationFolderId = it },
                            onAction = { action, destination ->
                                scope.launch {
                                    controller.mutateSelectedMessage(action, destination)
                                }
                            },
                            onDelete = { messageDeleteOpen = true },
                            modifier = Modifier.fillMaxSize(),
                        )

                        NarrowStage.Authentication -> AuthenticationProbePane(
                            controller = controller,
                            modifier = Modifier.fillMaxSize(),
                        )

                        NarrowStage.Trace -> TracePane(
                            controller = controller,
                            mode = traceMode,
                            onModeChanged = { traceMode = it },
                            onRefreshAccount = {
                                scope.launch { controller.refreshAccountLogs() }
                            },
                            onRefreshServer = { service ->
                                scope.launch { controller.refreshGlobalLogs(service) }
                            },
                            modifier = Modifier.fillMaxSize(),
                        )
                    }
                }
            }
        }
    }

    if (createAccountOpen) {
        CreateAccountDialog(
            busy = controller.busyLabel != null,
            onDismiss = { createAccountOpen = false },
            onCreate = { request ->
                createAccountOpen = false
                scope.launch { controller.createAccount(request) }
            },
        )
    }
    passwordMode?.let { initialMode ->
        PasswordDialog(
            target = controller.selectedTarget,
            initialMode = initialMode,
            busy = controller.busyLabel != null,
            onDismiss = { passwordMode = null },
            onSubmit = { mode, password ->
                passwordMode = null
                scope.launch {
                    when (mode) {
                        PasswordActionMode.VERIFY -> controller.adoptPassword(password)
                        PasswordActionMode.RESET -> controller.changePassword(password)
                    }
                }
            },
        )
    }
    if (accountDeleteOpen) {
        ConfirmDialog(
            title = "Delete account channel?",
            body = controller.selectedTarget?.let {
                "Delete ${it.address} from ${it.provider.displayName()} only. The other provider is not changed."
            } ?: "No account channel is selected.",
            confirmLabel = "Delete account",
            busy = controller.busyLabel != null,
            onDismiss = { accountDeleteOpen = false },
            onConfirm = {
                accountDeleteOpen = false
                scope.launch { controller.deleteSelectedAccount() }
            },
        )
    }
    if (createFolderOpen) {
        FolderDialog(
            target = controller.selectedTarget,
            busy = controller.busyLabel != null,
            onDismiss = { createFolderOpen = false },
            onCreate = { name ->
                createFolderOpen = false
                scope.launch { controller.createFolder(name) }
            },
        )
    }
    folderPendingDelete?.let { folder ->
        ConfirmDialog(
            title = "Delete folder?",
            body = "Delete ${folder.name} from ${controller.selectedTarget?.displayName.orEmpty()}?",
            confirmLabel = "Delete folder",
            busy = controller.busyLabel != null,
            onDismiss = { folderPendingDelete = null },
            onConfirm = {
                folderPendingDelete = null
                scope.launch { controller.deleteFolder(folder.id) }
            },
        )
    }
    if (generateOpen) {
        GenerateMessageDialog(
            accounts = controller.accounts,
            selectedTarget = controller.selectedTarget,
            selectedFolderId = controller.selectedFolderId,
            selectedTargetFolders = controller.folders,
            busy = controller.busyLabel != null,
            onDismiss = { generateOpen = false },
            onGenerate = { request ->
                generateOpen = false
                scope.launch { controller.generateMessage(request) }
            },
        )
    }
    if (messageDeleteOpen) {
        ConfirmDialog(
            title = "Delete message permanently?",
            body = "Delete the selected message from ${controller.selectedTarget?.displayName.orEmpty()}?",
            confirmLabel = "Delete message",
            busy = controller.busyLabel != null,
            onDismiss = { messageDeleteOpen = false },
            onConfirm = {
                messageDeleteOpen = false
                scope.launch { controller.mutateSelectedMessage(MessageAction.DELETE) }
            },
        )
    }
}

@Composable
private fun RuntimeStrip(
    state: GateState,
    resourceMarker: String,
    onAction: (GateAction) -> Unit,
    onRouteSelected: (GateRoute) -> Unit,
) {
    val incrementInteractionSource = remember { MutableInteractionSource() }
    val incrementFocused by incrementInteractionSource.collectIsFocusedAsState()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(DeepGraphite)
            .padding(horizontal = 12.dp, vertical = 5.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            StatusLamp(
                healthy = state.apiProbeMessage != null,
                label = "Local runtime",
            )
            RuntimeButton(
                label = "Overview",
                selected = state.route == GateRoute.Overview,
                onClick = { onRouteSelected(GateRoute.Overview) },
            )
            RuntimeButton(
                label = "Gate details",
                selected = state.route == GateRoute.Details,
                onClick = { onRouteSelected(GateRoute.Details) },
            )
            OutlinedButton(
                onClick = { onAction(GateAction.IncrementProof) },
                interactionSource = incrementInteractionSource,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = RecorderPaper),
                border = BorderStroke(1.dp, if (incrementFocused) RecorderCursorRed else SilkscreenGray),
                modifier = Modifier.height(32.dp),
                contentPadding = ButtonDefaults.TextButtonContentPadding,
            ) {
                Text("Increment proof", fontSize = 12.sp)
            }
            RuntimeNotation("Selected route: ${state.route.path}")
            RuntimeNotation("Activation count: ${state.activationCount}")
            RuntimeNotation(
                if (incrementFocused) "Keyboard focus: increment proof" else "Keyboard focus: none",
                color = if (incrementFocused) RecorderCursorRed else ShellLabel,
            )
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState())
                .semantics { liveRegion = LiveRegionMode.Polite },
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            RuntimeNotation("JSON API: ${state.apiProbeStatus.name.lowercase()}")
            RuntimeNotation("API message: ${state.apiProbeMessage ?: "pending"}")
            RuntimeNotation("SSE sequence: ${state.sseSequence ?: "pending"}")
            RuntimeNotation("Reconnect status: ${state.sseConnectionStatus.name.lowercase()}")
            RuntimeNotation("SSE sync: ${state.sseSyncStatus.name.lowercase()}")
            RuntimeNotation(resourceMarker)
        }
    }
}

@Composable
private fun RuntimeButton(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = RecorderPaper,
            containerColor = if (selected) SilkscreenGray else Color.Transparent,
        ),
        border = BorderStroke(1.dp, SilkscreenGray),
        modifier = Modifier
            .height(32.dp)
            .semantics { this.selected = selected },
        contentPadding = ButtonDefaults.TextButtonContentPadding,
    ) {
        Text(label, fontSize = 12.sp)
    }
}

@Composable
private fun RuntimeNotation(text: String, color: Color = ShellLabel) {
    Text(
        text = text,
        color = color,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        maxLines = 1,
    )
}

@Composable
private fun ProductHeader(
    controller: DashboardController,
    onAddAccount: () -> Unit,
    onGenerate: () -> Unit,
    onRefresh: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                text = "Mail Flight Recorder",
                color = RecorderPaper,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.semantics { heading() },
            )
            Text(
                text = "Local Dovecot + Stalwart debugging workbench",
                color = ShellLabel,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            ShellButton("Refresh", enabled = controller.busyLabel == null, onClick = onRefresh)
            ShellButton(
                "Generate message",
                enabled = controller.accounts.any {
                    it.credentialReadiness == CredentialReadiness.READY
                } && controller.busyLabel == null,
                onClick = onGenerate,
            )
            Button(
                onClick = onAddAccount,
                enabled = controller.busyLabel == null,
                colors = ButtonDefaults.buttonColors(
                    containerColor = RecorderPaper,
                    contentColor = InstrumentGraphite,
                ),
            ) {
                Text("Add account")
            }
        }
    }
    controller.busyLabel?.let { BusyBand(it) }
    controller.operationError?.let { ErrorState(it) }
}

@Composable
private fun ProviderStatusRail(
    statuses: List<ProviderStatus>,
    compact: Boolean,
) {
    val statusByProvider = statuses.associateBy(ProviderStatus::provider)
    val modifier = Modifier
        .fillMaxWidth()
        .padding(start = 12.dp, end = 12.dp, bottom = 8.dp)
    if (compact) {
        Column(
            modifier = modifier,
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Provider.entries.forEach { provider ->
                ProviderStatusBanner(
                    provider = provider,
                    status = statusByProvider[provider],
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    } else {
        Row(
            modifier = modifier,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Provider.entries.forEach { provider ->
                ProviderStatusBanner(
                    provider = provider,
                    status = statusByProvider[provider],
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun ProviderStatusBanner(
    provider: Provider,
    status: ProviderStatus?,
    modifier: Modifier = Modifier,
) {
    val availability = status?.availability
    val label = when (availability) {
        ProviderAvailability.READY -> "Ready"
        ProviderAvailability.DEGRADED -> "Degraded"
        ProviderAvailability.UNAVAILABLE -> "Unavailable"
        ProviderAvailability.UPGRADE_REQUIRED -> "Upgrade required"
        null -> "Checking"
    }
    val background = when (availability) {
        ProviderAvailability.READY -> GreenWash
        ProviderAvailability.DEGRADED,
        ProviderAvailability.UPGRADE_REQUIRED,
        -> StalwartWash
        ProviderAvailability.UNAVAILABLE -> ErrorWash
        null -> PanelFog
    }
    val lampHealthy = availability == ProviderAvailability.READY
    Row(
        modifier = modifier
            .background(background)
            .border(1.dp, provider.channelColor())
            .padding(horizontal = 9.dp, vertical = 6.dp)
            .semantics {
                contentDescription =
                    "Provider status ${provider.displayName()}: ${label.lowercase()}"
                liveRegion = LiveRegionMode.Polite
            },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        StatusLamp(
            healthy = lampHealthy,
            label = "${provider.displayName()} · $label",
            labelColor = InstrumentGraphite,
        )
        status?.message?.takeIf(String::isNotBlank)?.let { message ->
            Text(
                text = message,
                modifier = Modifier.weight(1f),
                color = InstrumentGraphite,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun ShellButton(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        colors = ButtonDefaults.outlinedButtonColors(contentColor = RecorderPaper),
        border = BorderStroke(1.dp, ShellLabel),
    ) {
        Text(label)
    }
}

@Composable
private fun BusyBand(label: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(PanelFogDark)
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(14.dp),
            strokeWidth = 2.dp,
            color = InstrumentGraphite,
        )
        Text(label, color = InstrumentGraphite, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun AccountsPane(
    controller: DashboardController,
    onSelect: (AccountTarget) -> Unit,
    onAdd: () -> Unit,
    modifier: Modifier = Modifier,
) {
    WorkZone(
        label = "Account channels",
        modifier = modifier,
        headerAction = {
            TextButton(onClick = onAdd, enabled = controller.busyLabel == null) {
                Text("New")
            }
        },
    ) {
        when {
            controller.accountsLoading && controller.accounts.isEmpty() -> LoadingState("Reading provider accounts")
            controller.accountError != null && controller.accounts.isEmpty() -> ErrorState(controller.accountError!!)
            controller.accounts.isEmpty() -> EmptyState(
                title = "No account channels",
                detail = "Create a Dovecot or Stalwart test account to start a reproduction.",
                actionLabel = "Create account",
                onAction = onAdd,
            )
            else -> {
                Column(
                    modifier = Modifier.fillMaxSize(),
                ) {
                    controller.accountError?.let { ErrorState(it) }
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState()),
                    ) {
                        controller.accounts
                            .groupBy(AccountInfo::address)
                            .toList()
                            .sortedBy { (address, _) -> address }
                            .forEach { (address, channels) ->
                                AccountGroup(
                                    address = address,
                                    channels = channels,
                                    selected = controller.selectedTarget,
                                    onSelect = onSelect,
                                )
                                HorizontalDivider(color = PanelFogDark)
                            }
                    }
                }
            }
        }
    }
}

@Composable
private fun AccountGroup(
    address: String,
    channels: List<AccountInfo>,
    selected: AccountTarget?,
    onSelect: (AccountTarget) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 10.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        Text(
            text = address,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        channels.sortedBy { it.provider.ordinal }.forEach { account ->
            ProviderChannelButton(
                account = account,
                selected = selected == account.target(),
                onClick = { onSelect(account.target()) },
            )
        }
    }
}

@Composable
private fun ProviderChannelButton(
    account: AccountInfo,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val channel = account.provider.channelColor()
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .width(5.dp)
                .height(76.dp)
                .background(channel),
        )
        OutlinedButton(
            onClick = onClick,
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = InstrumentGraphite,
                containerColor = if (selected) account.provider.channelWash() else RecorderPaper,
            ),
            border = BorderStroke(1.dp, if (selected) channel else PanelFogDark),
            modifier = Modifier
                .weight(1f)
                .heightIn(min = 76.dp)
                .semantics { this.selected = selected },
            contentPadding = ButtonDefaults.TextButtonContentPadding,
        ) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(5.dp),
                ) {
                    Text(
                        account.provider.displayName(),
                        modifier = Modifier.weight(1f),
                        fontWeight = FontWeight.SemiBold,
                    )
                    ReadinessBadge(account.credentialReadiness)
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    account.protocols.forEach { protocol ->
                        ProtocolChip(protocol = protocol, stale = account.stale)
                    }
                }
                if (account.stale) {
                    StaleMarker()
                }
            }
        }
    }
}

@Composable
private fun ReadinessBadge(readiness: CredentialReadiness) {
    val label = readiness.displayName()
    val background = when (readiness) {
        CredentialReadiness.READY -> GreenWash
        CredentialReadiness.PASSWORD_REQUIRED -> StalwartWash
        CredentialReadiness.AUTHENTICATION_FAILED -> ErrorWash
        CredentialReadiness.PROVIDER_UNAVAILABLE -> PanelFogDark
    }
    val content = when (readiness) {
        CredentialReadiness.READY -> VerifiedGreen
        CredentialReadiness.PASSWORD_REQUIRED -> InstrumentGraphite
        CredentialReadiness.AUTHENTICATION_FAILED -> RecorderCursorRed
        CredentialReadiness.PROVIDER_UNAVAILABLE -> SilkscreenGray
    }
    Text(
        text = label,
        modifier = Modifier
            .background(background, RoundedCornerShape(50))
            .padding(horizontal = 6.dp, vertical = 2.dp)
            .semantics {
                contentDescription = "Readiness ${readiness.name.lowercase()}"
            },
        color = content,
        fontSize = 10.sp,
        fontWeight = FontWeight.SemiBold,
        maxLines = 1,
    )
}

@Composable
private fun StaleMarker() {
    Text(
        text = "Stale snapshot",
        modifier = Modifier
            .border(1.dp, SilkscreenGray, RoundedCornerShape(50))
            .padding(horizontal = 6.dp, vertical = 2.dp)
            .semantics { contentDescription = "Stale provider snapshot" },
        color = SilkscreenGray,
        fontSize = 10.sp,
        maxLines = 1,
    )
}

@Composable
private fun ProtocolChip(
    protocol: MailProtocol,
    stale: Boolean,
) {
    val evidence = if (stale) "cached" else "live"
    Text(
        text = protocol.name,
        modifier = Modifier
            .background(if (stale) PanelFog else RecorderPaper)
            .border(1.dp, if (stale) SilkscreenGray else InstrumentGraphite, RoundedCornerShape(2.dp))
            .padding(horizontal = 5.dp, vertical = 2.dp)
            .semantics {
                contentDescription = "Protocol ${protocol.name}: $evidence"
            },
        color = if (stale) SilkscreenGray else InstrumentGraphite,
        fontFamily = FontFamily.Monospace,
        fontSize = 10.sp,
        maxLines = 1,
    )
}

@Composable
private fun ReadinessNotice(
    account: AccountInfo,
    enabled: Boolean,
    onVerifyPassword: () -> Unit,
    onRefresh: () -> Unit,
) {
    val message = account.readinessMessage?.takeIf(String::isNotBlank)
        ?: account.credentialReadiness.defaultMessage()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (account.credentialReadiness == CredentialReadiness.AUTHENTICATION_FAILED) {
                    ErrorWash
                } else {
                    PanelFog
                },
            )
            .padding(horizontal = 10.dp, vertical = 6.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = message,
            modifier = Modifier.weight(1f),
            color = InstrumentGraphite,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        when (account.credentialReadiness) {
            CredentialReadiness.PASSWORD_REQUIRED,
            CredentialReadiness.AUTHENTICATION_FAILED,
            -> TextButton(onClick = onVerifyPassword, enabled = enabled) {
                Text("Verify existing password")
            }
            CredentialReadiness.PROVIDER_UNAVAILABLE ->
                TextButton(onClick = onRefresh, enabled = enabled) { Text("Retry provider") }
            CredentialReadiness.READY -> {
                if (account.stale) {
                    TextButton(onClick = onRefresh, enabled = enabled) { Text("Refresh provider") }
                }
            }
        }
    }
}

@Composable
private fun AccountHeader(
    controller: DashboardController,
    onVerifyPassword: () -> Unit,
    onResetPassword: () -> Unit,
    onDelete: () -> Unit,
    onRefresh: () -> Unit,
) {
    val account = controller.selectedAccount
    Surface(
        color = RecorderPaper,
        contentColor = InstrumentGraphite,
        shape = MaterialTheme.shapes.small,
        border = BorderStroke(1.dp, SilkscreenGray),
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (account == null) {
            Text(
                "Select an account channel to inspect its mailbox.",
                modifier = Modifier.padding(14.dp),
                color = SilkscreenGray,
            )
        } else {
            Column(Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Box(
                        Modifier
                            .width(6.dp)
                            .height(88.dp)
                            .background(account.provider.channelColor()),
                    )
                    Column(
                        modifier = Modifier
                            .weight(1f)
                            .padding(horizontal = 12.dp, vertical = 9.dp),
                        verticalArrangement = Arrangement.spacedBy(5.dp),
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(7.dp),
                        ) {
                            Text(
                                account.address,
                                modifier = Modifier.weight(1f),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            ReadinessBadge(account.credentialReadiness)
                            if (account.stale) StaleMarker()
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            account.protocols.forEach { protocol ->
                                ProtocolChip(protocol = protocol, stale = account.stale)
                            }
                        }
                    }
                    Row(
                        modifier = Modifier
                            .padding(8.dp)
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        OutlinedButton(
                            onClick = onRefresh,
                            enabled = controller.busyLabel == null,
                        ) { Text("Refresh") }
                        OutlinedButton(
                            onClick = onVerifyPassword,
                            enabled = controller.busyLabel == null,
                        ) { Text("Verify existing password") }
                        OutlinedButton(
                            onClick = onResetPassword,
                            enabled = controller.busyLabel == null,
                        ) { Text("Reset password") }
                        TextButton(
                            onClick = onDelete,
                            enabled = controller.busyLabel == null,
                            colors = ButtonDefaults.textButtonColors(contentColor = RecorderCursorRed),
                        ) { Text("Delete account") }
                    }
                }
                if (account.credentialReadiness != CredentialReadiness.READY || account.stale) {
                    ReadinessNotice(
                        account = account,
                        enabled = controller.busyLabel == null,
                        onVerifyPassword = onVerifyPassword,
                        onRefresh = onRefresh,
                    )
                }
            }
        }
    }
}

@Composable
private fun CompactAccountSummary(account: AccountInfo?) {
    if (account == null) return
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(RecorderPaper)
            .border(1.dp, SilkscreenGray)
            .padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(
            Modifier
                .width(5.dp)
                .height(32.dp)
                .background(account.provider.channelColor()),
        )
        Column(Modifier.weight(1f)) {
            Text(account.address, fontFamily = FontFamily.Monospace, maxLines = 1)
            Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(
                    account.provider.displayName(),
                    color = SilkscreenGray,
                    style = MaterialTheme.typography.bodySmall,
                )
                ReadinessBadge(account.credentialReadiness)
                if (account.stale) StaleMarker()
            }
        }
    }
}

@Composable
private fun NarrowStageRail(
    stage: NarrowStage,
    onStageSelected: (NarrowStage) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        NarrowStage.entries.forEach { candidate ->
            SelectionButton(
                label = candidate.label,
                selected = candidate == stage,
                onClick = { onStageSelected(candidate) },
            )
        }
    }
}

@Composable
private fun MailboxPane(
    controller: DashboardController,
    compact: Boolean,
    onCreateFolder: () -> Unit,
    onDeleteFolder: (FolderInfo) -> Unit,
    onSelectFolder: (String) -> Unit,
    onSelectMessage: (MessageSummary) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (compact) {
        Column(
            modifier = modifier,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FolderPane(
                controller = controller,
                onCreate = onCreateFolder,
                onDelete = onDeleteFolder,
                onSelect = onSelectFolder,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 150.dp, max = 240.dp),
            )
            MessagesPane(
                controller = controller,
                onSelect = onSelectMessage,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )
        }
    } else {
        Row(
            modifier = modifier,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FolderPane(
                controller = controller,
                onCreate = onCreateFolder,
                onDelete = onDeleteFolder,
                onSelect = onSelectFolder,
                modifier = Modifier
                    .width(210.dp)
                    .fillMaxHeight(),
            )
            MessagesPane(
                controller = controller,
                onSelect = onSelectMessage,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxHeight(),
            )
        }
    }
}

@Composable
private fun FolderPane(
    controller: DashboardController,
    onCreate: () -> Unit,
    onDelete: (FolderInfo) -> Unit,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    WorkZone(
        label = "Folders",
        modifier = modifier,
        headerAction = {
            TextButton(
                onClick = onCreate,
                enabled = controller.mailActionsEnabled && controller.busyLabel == null,
            ) { Text("New") }
        },
    ) {
        when {
            controller.selectedTarget == null -> EmptyState("No account selected", "Choose an account channel first.")
            !controller.mailActionsEnabled -> MailReadinessEmptyState(controller.selectedAccount)
            controller.workspaceLoading && controller.folders.isEmpty() -> LoadingState("Reading folders")
            controller.folders.isEmpty() -> EmptyState(
                "No folders returned",
                "Create a folder or refresh the selected provider.",
                "Create folder",
                onCreate,
            )
            else -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
            ) {
                controller.folders.forEach { folder ->
                    FolderRow(
                        folder = folder,
                        selected = folder.id == controller.selectedFolderId,
                        onSelect = { onSelect(folder.id) },
                        onDelete = { onDelete(folder) },
                        canDelete = !folder.isInbox() && controller.busyLabel == null,
                    )
                }
            }
        }
    }
}

@Composable
private fun FolderRow(
    folder: FolderInfo,
    selected: Boolean,
    onSelect: () -> Unit,
    onDelete: () -> Unit,
    canDelete: Boolean,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (selected) PanelFogDark else RecorderPaper)
            .clickable(onClick = onSelect)
            .semantics {
                this.selected = selected
                role = Role.Button
            }
            .padding(start = 10.dp, top = 8.dp, bottom = 8.dp, end = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(folder.name, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal)
            Text(
                "${folder.unreadMessages} unread / ${folder.totalMessages} total",
                color = SilkscreenGray,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
            )
        }
        if (!folder.isInbox()) {
            TextButton(onClick = onDelete, enabled = canDelete) {
                Text("Delete")
            }
        }
    }
    HorizontalDivider(color = PanelFogDark)
}

private fun FolderInfo.isInbox(): Boolean =
    id.equals("INBOX", ignoreCase = true) || name.equals("Inbox", ignoreCase = true)

@Composable
private fun MessagesPane(
    controller: DashboardController,
    onSelect: (MessageSummary) -> Unit,
    modifier: Modifier = Modifier,
) {
    WorkZone(
        label = controller.selectedFolder?.let { "Messages · ${it.name}" } ?: "Messages",
        modifier = modifier,
    ) {
        Column(Modifier.fillMaxSize()) {
            controller.workspaceError?.let { ErrorState(it) }
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
            ) {
                when {
                    controller.selectedTarget == null -> EmptyState("No account selected", "Choose an account channel first.")
                    !controller.mailActionsEnabled -> MailReadinessEmptyState(controller.selectedAccount)
                    controller.workspaceLoading && controller.messages.isEmpty() -> LoadingState("Reading messages")
                    controller.messages.isEmpty() -> EmptyState(
                        "This folder is empty",
                        "Generate an EML, authored text message, or deterministic random fixture.",
                    )
                    else -> Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState()),
                    ) {
                        controller.messages.forEach { message ->
                            MessageRow(
                                message = message,
                                selected = message.id == controller.selectedMessageId,
                                provider = controller.selectedTarget?.provider,
                                onClick = { onSelect(message) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun MessageRow(
    message: MessageSummary,
    selected: Boolean,
    provider: Provider?,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (selected) PanelFogDark else RecorderPaper)
            .clickable(onClick = onClick)
            .semantics {
                this.selected = selected
                role = Role.Button
                contentDescription = buildString {
                    append(if (message.isRead) "Read" else "Unread")
                    if (message.isFlagged) append(", flagged")
                    append(", ")
                    append(message.subject ?: "No subject")
                    append(", from ")
                    append(message.fromAddress ?: "unknown sender")
                }
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        provider?.let {
            Box(
                Modifier
                    .width(4.dp)
                    .height(74.dp)
                    .background(it.channelColor()),
            )
        }
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = message.subject ?: "(no subject)",
                    modifier = Modifier.weight(1f),
                    fontWeight = if (message.isRead) FontWeight.Normal else FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (message.isFlagged) {
                    Text("★", color = StalwartAmber, fontSize = 13.sp)
                }
            }
            Text(
                text = message.fromAddress ?: "Unknown sender",
                color = SilkscreenGray,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "${if (message.isRead) "READ" else "UNREAD"} · ${message.receivedAt ?: "time unavailable"} · id ${message.id}",
                color = SilkscreenGray,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
    HorizontalDivider(color = PanelFogDark)
}

@Composable
private fun MessageReaderPane(
    controller: DashboardController,
    destinationFolderId: String?,
    onDestinationChanged: (String?) -> Unit,
    onAction: (MessageAction, String?) -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    WorkZone(label = "Message reader + operations", modifier = modifier) {
        when {
            controller.selectedTarget != null && !controller.mailActionsEnabled ->
                MailReadinessEmptyState(controller.selectedAccount)
            controller.messageLoading -> LoadingState("Reading message body")
            controller.selectedMessage == null -> EmptyState(
                "No message selected",
                "Choose a message to inspect content and execute mail operations.",
            )
            else -> MessageReader(
                message = controller.selectedMessage!!,
                folders = controller.folders,
                destinationFolderId = destinationFolderId,
                busy = controller.busyLabel != null,
                mailActionsEnabled = controller.mailActionsEnabled,
                onDestinationChanged = onDestinationChanged,
                onAction = onAction,
                onDelete = onDelete,
            )
        }
    }
}

@Composable
private fun ColumnScope.MessageReader(
    message: MessageDetail,
    folders: List<FolderInfo>,
    destinationFolderId: String?,
    busy: Boolean,
    mailActionsEnabled: Boolean,
    onDestinationChanged: (String?) -> Unit,
    onAction: (MessageAction, String?) -> Unit,
    onDelete: () -> Unit,
) {
    Column(
        modifier = Modifier
            .weight(1f)
            .fillMaxWidth()
            .verticalScroll(rememberScrollState()),
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            Text(
                message.subject ?: "(no subject)",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.semantics { heading() },
            )
            EvidenceLine("From", message.fromAddress ?: "Unknown sender")
            EvidenceLine("To", message.toAddresses.joinToString().ifBlank { "Unknown recipient" })
            EvidenceLine("Sent", message.sentAt ?: "Unavailable")
            EvidenceLine("Message ID", message.id)
            EvidenceLine(
                "State",
                listOfNotNull(
                    if (message.isRead) "read" else "unread",
                    "flagged".takeIf { message.isFlagged },
                ).joinToString(" / "),
            )
        }
        HorizontalDivider(color = PanelFogDark)
        Text(
            text = message.textBody ?: message.htmlBody ?: "No readable body was returned.",
            modifier = Modifier.padding(14.dp),
            style = MaterialTheme.typography.bodyMedium,
            lineHeight = 20.sp,
        )
    }
    HorizontalDivider(color = PanelFogDark)
    Column(
        modifier = Modifier.padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            OperationButton(
                label = if (message.isRead) "Mark unread" else "Mark read",
                enabled = mailActionsEnabled && !busy,
                onClick = {
                    onAction(
                        if (message.isRead) MessageAction.MARK_UNREAD else MessageAction.MARK_READ,
                        null,
                    )
                },
            )
            OperationButton(
                label = if (message.isFlagged) "Unflag" else "Flag",
                enabled = mailActionsEnabled && !busy,
                onClick = {
                    onAction(
                        if (message.isFlagged) MessageAction.UNFLAG else MessageAction.FLAG,
                        null,
                    )
                },
            )
            OperationButton("Trash", enabled = mailActionsEnabled && !busy) {
                onAction(MessageAction.TRASH, null)
            }
            TextButton(
                onClick = onDelete,
                enabled = mailActionsEnabled && !busy,
                colors = ButtonDefaults.textButtonColors(contentColor = RecorderCursorRed),
            ) { Text("Delete permanently") }
        }
        val destinations = folders.filterNot { it.id == message.folderId }
        if (destinations.isNotEmpty()) {
            val selectedDestination = destinationFolderId?.takeIf { candidate ->
                destinations.any { it.id == candidate }
            }
            Text(
                "Move / copy destination",
                color = SilkscreenGray,
                style = MaterialTheme.typography.labelMedium,
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                destinations.forEach { folder ->
                    SelectionButton(
                        label = folder.name,
                        selected = selectedDestination == folder.id,
                        onClick = { onDestinationChanged(folder.id) },
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                OperationButton(
                    "Move",
                    enabled = mailActionsEnabled && selectedDestination != null && !busy,
                ) { onAction(MessageAction.MOVE, selectedDestination) }
                OperationButton(
                    "Copy",
                    enabled = mailActionsEnabled && selectedDestination != null && !busy,
                ) { onAction(MessageAction.COPY, selectedDestination) }
            }
        }
    }
}

@Composable
private fun OperationButton(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    OutlinedButton(onClick = onClick, enabled = enabled) { Text(label) }
}

@Composable
private fun TracePane(
    controller: DashboardController,
    mode: TraceMode,
    onModeChanged: (TraceMode) -> Unit,
    onRefreshAccount: () -> Unit,
    onRefreshServer: (LogService) -> Unit,
    modifier: Modifier = Modifier,
) {
    val logsLoading = if (mode == TraceMode.Account) {
        controller.accountLogsLoading
    } else {
        controller.globalLogsLoading
    }
    val logsError = if (mode == TraceMode.Account) {
        controller.accountLogsError
    } else {
        controller.globalLogsError
    }
    WorkZone(label = "Trace lens", modifier = modifier) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            controller.lastReceipt?.let { ReceiptState(it) }
            logsError?.let { ErrorState(it) }
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                TraceMode.entries.forEach { candidate ->
                    SelectionButton(
                        label = candidate.label,
                        selected = mode == candidate,
                        onClick = { onModeChanged(candidate) },
                    )
                }
            }
            if (mode == TraceMode.Server) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(5.dp),
                ) {
                    LogService.entries.forEach { service ->
                        SelectionButton(
                            label = service.displayName(),
                            selected = service == controller.globalLogService,
                            onClick = { onRefreshServer(service) },
                            compact = true,
                        )
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    if (mode == TraceMode.Account) {
                        controller.selectedTarget?.displayName ?: "No account selected"
                    } else {
                        "${controller.globalLogService.displayName()} services"
                    },
                    modifier = Modifier.weight(1f),
                    color = SilkscreenGray,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                TextButton(
                    onClick = {
                        if (mode == TraceMode.Account) onRefreshAccount()
                        else onRefreshServer(controller.globalLogService)
                    },
                    enabled = !logsLoading &&
                        (mode == TraceMode.Server || controller.selectedTarget != null),
                ) { Text("Refresh logs") }
            }
            if (logsLoading) {
                LoadingState("Reading logs")
            } else {
                val response = if (mode == TraceMode.Account) controller.accountLogs else controller.globalLogs
                LogLines(response, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun LogLines(response: LogResponse?, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        color = DeepGraphite,
        contentColor = RecorderPaper,
        shape = MaterialTheme.shapes.extraSmall,
    ) {
        when {
            response == null -> Text(
                "No trace loaded.",
                modifier = Modifier.padding(10.dp),
                color = ShellLabel,
            )
            response.lines.isEmpty() -> Text(
                "No matching log lines.",
                modifier = Modifier.padding(10.dp),
                color = ShellLabel,
            )
            else -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                response.lines.forEach { line ->
                    Text(
                        line,
                        color = RecorderPaper,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun WorkZone(
    label: String,
    modifier: Modifier = Modifier,
    headerAction: (@Composable RowScope.() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        modifier = modifier,
        color = RecorderPaper,
        contentColor = InstrumentGraphite,
        shape = MaterialTheme.shapes.small,
        border = BorderStroke(1.dp, SilkscreenGray),
    ) {
        Column(Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(PanelFog)
                    .heightIn(min = 40.dp)
                    .padding(start = 10.dp, end = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    label,
                    modifier = Modifier
                        .weight(1f)
                        .semantics { heading() },
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                headerAction?.invoke(this)
            }
            HorizontalDivider(color = SilkscreenGray)
            content()
        }
    }
}

@Composable
private fun LoadingState(label: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(14.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
        Text(label, color = SilkscreenGray)
    }
}

@Composable
private fun ErrorState(message: String) {
    Text(
        text = "$message. Check the local provider and retry.",
        modifier = Modifier
            .fillMaxWidth()
            .background(ErrorWash)
            .padding(10.dp)
            .semantics { liveRegion = LiveRegionMode.Assertive },
        color = InstrumentGraphite,
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun ReceiptState(message: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(GreenWash)
            .padding(8.dp)
            .semantics { liveRegion = LiveRegionMode.Polite },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(7.dp),
    ) {
        StatusLamp(true, "Completed", labelColor = InstrumentGraphite)
        Text(message, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun EmptyState(
    title: String,
    detail: String,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(title, fontWeight = FontWeight.SemiBold)
        Text(detail, color = SilkscreenGray, style = MaterialTheme.typography.bodySmall)
        if (actionLabel != null && onAction != null) {
            OutlinedButton(onClick = onAction) { Text(actionLabel) }
        }
    }
}

@Composable
private fun MailReadinessEmptyState(account: AccountInfo?) {
    val readiness = account?.credentialReadiness ?: return
    val title = readiness.displayName()
    val detail = when (readiness) {
        CredentialReadiness.READY -> "Mail operations are ready. Refresh the selected provider."
        CredentialReadiness.PASSWORD_REQUIRED ->
            "Verify the existing password or reset it before reading or changing mailbox state."
        CredentialReadiness.AUTHENTICATION_FAILED ->
            "The remembered password no longer authenticates. Verify or reset it, then retry."
        CredentialReadiness.PROVIDER_UNAVAILABLE ->
            "The provider could not verify this account. Retry the provider before using mail operations."
    }
    EmptyState(title = title, detail = detail)
}

@Composable
private fun StatusLamp(
    healthy: Boolean,
    label: String,
    labelColor: Color = ShellLabel,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp),
        modifier = Modifier.semantics {
            contentDescription = "$label: ${if (healthy) "ready" else "not ready"}"
        },
    ) {
        Box(
            Modifier
                .size(8.dp)
                .background(
                    if (healthy) VerifiedGreen else RecorderCursorRed,
                    RoundedCornerShape(50),
                ),
        )
        Text(label, color = labelColor, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
private fun SelectionButton(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    compact: Boolean = false,
    enabled: Boolean = true,
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        colors = ButtonDefaults.outlinedButtonColors(
            containerColor = if (selected) InstrumentGraphite else RecorderPaper,
            contentColor = if (selected) RecorderPaper else InstrumentGraphite,
        ),
        border = BorderStroke(1.dp, InstrumentGraphite),
        modifier = Modifier
            .height(if (compact) 32.dp else 38.dp)
            .semantics { this.selected = selected },
        contentPadding = if (compact) ButtonDefaults.TextButtonContentPadding else ButtonDefaults.ContentPadding,
    ) {
        Text(label, fontSize = if (compact) 11.sp else 13.sp)
    }
}

@Composable
private fun EvidenceLine(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            label,
            modifier = Modifier.width(72.dp),
            color = SilkscreenGray,
            style = MaterialTheme.typography.labelSmall,
        )
        Text(
            value,
            modifier = Modifier.weight(1f),
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun CreateAccountDialog(
    busy: Boolean,
    onDismiss: () -> Unit,
    onCreate: (CreateAccountRequest) -> Unit,
) {
    var address by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var provider by remember { mutableStateOf(Provider.DOVECOT) }
    var protocols by remember {
        mutableStateOf(STALWART_SELECTABLE_PROTOCOLS.toSet())
    }
    val requestedProtocols = provider.creationProtocols(protocols)
    val canCreate = address.isNotBlank() &&
        password.isNotBlank() &&
        requestedProtocols.isNotEmpty() &&
        !busy

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Create account channel", provider) },
        text = {
            Column(
                modifier = Modifier
                    .widthIn(min = 300.dp, max = 560.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    "Create one provider-backed account. The same address can be registered on the other provider separately.",
                    color = SilkscreenGray,
                )
                Text("Provider", fontWeight = FontWeight.SemiBold)
                Row(horizontalArrangement = Arrangement.spacedBy(7.dp)) {
                    Provider.entries.forEach { candidate ->
                        ProviderSelectionButton(
                            provider = candidate,
                            selected = provider == candidate,
                            onClick = {
                                provider = candidate
                                protocols = STALWART_SELECTABLE_PROTOCOLS.toSet()
                            },
                        )
                    }
                }
                OutlinedTextField(
                    value = address,
                    onValueChange = { address = it },
                    label = { Text("Email address") },
                    supportingText = { Text("Use a local.test address, for example repro@local.test") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Account password") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("Client protocol profile", fontWeight = FontWeight.SemiBold)
                when (provider) {
                    Provider.DOVECOT -> {
                        Text(
                            "Dovecot fixed account capabilities",
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            "Every Dovecot account uses the server-wide IMAP, POP3, and SMTP test profile.",
                            color = SilkscreenGray,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(5.dp),
                        ) {
                            DOVECOT_FIXED_PROTOCOLS.forEach { protocol ->
                                ProtocolChip(protocol = protocol, stale = false)
                            }
                        }
                    }
                    Provider.STALWART -> {
                        Text(
                            "Select the enforced Stalwart account permissions. At least one is required.",
                            color = SilkscreenGray,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        STALWART_SELECTABLE_PROTOCOLS.forEach { protocol ->
                            ProtocolToggle(
                                protocol = protocol,
                                checked = protocol in protocols,
                                onCheckedChange = { checked ->
                                    protocols = if (checked) protocols + protocol else protocols - protocol
                                },
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onCreate(
                        CreateAccountRequest(
                            address = address.trim(),
                            password = password,
                            provider = provider,
                            protocols = provider.creationProtocols(protocols),
                        ),
                    )
                },
                enabled = canCreate,
            ) { Text("Create account") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ProtocolToggle(
    protocol: MailProtocol,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(
                value = checked,
                role = Role.Checkbox,
                onValueChange = onCheckedChange,
            )
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = null)
        Column {
            Text(protocol.name, fontFamily = FontFamily.Monospace)
            Text(protocol.description(), color = SilkscreenGray, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun PasswordDialog(
    target: AccountTarget?,
    initialMode: PasswordActionMode,
    busy: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (PasswordActionMode, String) -> Unit,
) {
    var mode by remember(initialMode) { mutableStateOf(initialMode) }
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Account password", target?.provider) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(target?.displayName ?: "No account selected", fontFamily = FontFamily.Monospace)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    SelectionButton(
                        label = "Verify existing password",
                        selected = mode == PasswordActionMode.VERIFY,
                        onClick = {
                            mode = PasswordActionMode.VERIFY
                            password = ""
                        },
                    )
                    SelectionButton(
                        label = "Reset password",
                        selected = mode == PasswordActionMode.RESET,
                        onClick = {
                            mode = PasswordActionMode.RESET
                            password = ""
                        },
                    )
                }
                Text(
                    if (mode == PasswordActionMode.VERIFY) {
                        "Verify the account's current ordinary password and remember it for this local dashboard."
                    } else {
                        "Replace the provider password, verify the new ordinary login, and remember it locally."
                    },
                    color = SilkscreenGray,
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = {
                        Text(
                            if (mode == PasswordActionMode.VERIFY) {
                                "Existing password"
                            } else {
                                "New password"
                            },
                        )
                    },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onSubmit(mode, password) },
                enabled = password.isNotBlank() && target != null && !busy,
            ) { Text(mode.label) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun AuthenticationProbePane(
    controller: DashboardController,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val account = controller.selectedAccount
    val supportedProtocols = account?.supportedAuthenticationProtocols().orEmpty()
    var protocol by remember(account?.target()) {
        mutableStateOf(supportedProtocols.firstOrNull())
    }
    var credentialSource by remember(account?.target(), account?.credentialReadiness) {
        mutableStateOf(
            if (account?.credentialReadiness == CredentialReadiness.PASSWORD_REQUIRED) {
                ProbeCredentialSource.OVERRIDE
            } else {
                ProbeCredentialSource.REMEMBERED
            },
        )
    }
    var credentialOverride by remember(account?.target()) { mutableStateOf("") }
    val selectedProtocol = protocol?.takeIf(supportedProtocols::contains)
        ?: supportedProtocols.firstOrNull()
    val protocolRequiresOverride = selectedProtocol?.requiresOverride() == true
    val rememberedAvailable = account != null &&
        account.credentialReadiness != CredentialReadiness.PASSWORD_REQUIRED &&
        !protocolRequiresOverride
    val usesOverride = credentialSource == ProbeCredentialSource.OVERRIDE || !rememberedAvailable
    val canProbe = account != null &&
        selectedProtocol != null &&
        (!usesOverride || credentialOverride.isNotBlank()) &&
        !controller.authenticationProbeLoading

    WorkZone(label = "Authentication probe", modifier = modifier) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp)
                .verticalScroll(rememberScrollState())
                .semantics { contentDescription = "Authentication probe panel" },
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            when {
                account == null -> EmptyState(
                    title = "No account selected",
                    detail = "Choose one provider channel to reproduce an authentication exchange.",
                )
                supportedProtocols.isEmpty() -> EmptyState(
                    title = "No explicit probes available",
                    detail = "This provider channel does not report a supported authentication protocol.",
                )
                else -> {
                    Text(
                        "${account.provider.displayName()} · ${account.address}",
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        "Protocol",
                        color = SilkscreenGray,
                        style = MaterialTheme.typography.labelMedium,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                    ) {
                        supportedProtocols.forEach { candidate ->
                            SelectionButton(
                                label = candidate.displayName(),
                                selected = candidate == selectedProtocol,
                                onClick = {
                                    protocol = candidate
                                    if (candidate.requiresOverride()) {
                                        credentialSource = ProbeCredentialSource.OVERRIDE
                                    }
                                    credentialOverride = ""
                                },
                                compact = true,
                            )
                        }
                    }
                    Text(
                        "Credential",
                        color = SilkscreenGray,
                        style = MaterialTheme.typography.labelMedium,
                    )
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(5.dp),
                    ) {
                        SelectionButton(
                            label = "Remembered credential",
                            selected = !usesOverride,
                            enabled = rememberedAvailable,
                            onClick = {
                                credentialSource = ProbeCredentialSource.REMEMBERED
                                credentialOverride = ""
                            },
                            compact = true,
                        )
                        SelectionButton(
                            label = "Request override",
                            selected = usesOverride,
                            onClick = { credentialSource = ProbeCredentialSource.OVERRIDE },
                            compact = true,
                        )
                    }
                    if (usesOverride) {
                        OutlinedTextField(
                            value = credentialOverride,
                            onValueChange = { credentialOverride = it },
                            label = {
                                Text(
                                    if (selectedProtocol?.requiresOverride() == true) {
                                        "OAuth token override"
                                    } else {
                                        "Password override"
                                    },
                                )
                            },
                            supportingText = {
                                Text("Used for this probe only; never remembered or shown in evidence.")
                            },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    Button(
                        onClick = {
                            val requestedProtocol = requireNotNull(selectedProtocol)
                            val override = credentialOverride.takeIf { usesOverride }
                            credentialOverride = ""
                            scope.launch {
                                controller.probeAuthentication(
                                    protocol = requestedProtocol,
                                    credentialOverride = override,
                                )
                            }
                        },
                        enabled = canProbe,
                    ) { Text("Run authentication probe") }
                    if (
                        account.credentialReadiness == CredentialReadiness.PASSWORD_REQUIRED &&
                        credentialOverride.isBlank() &&
                        !controller.authenticationProbeLoading
                    ) {
                        Text(
                            "Password required: enter a request override to keep this diagnostic available.",
                            color = SilkscreenGray,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
            if (controller.authenticationProbeLoading) {
                LoadingState("Waiting for bounded provider response")
            }
            controller.authenticationProbeError?.let { ErrorState(it) }
            controller.authenticationProbe?.let { ProbeResult(it) }
        }
    }
}

@Composable
private fun ProbeResult(result: AuthenticationProbeResponse) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (result.success) GreenWash else ErrorWash)
            .border(1.dp, if (result.success) VerifiedGreen else RecorderCursorRed)
            .padding(8.dp)
            .semantics {
                liveRegion = LiveRegionMode.Polite
                contentDescription = if (result.success) "Authentication probe passed" else "Authentication probe failed"
            },
        verticalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Text(
            if (result.success) "Probe passed" else "Probe failed",
            color = if (result.success) VerifiedGreen else RecorderCursorRed,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            "${result.provider.displayName()} · ${result.protocol.displayName()}",
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            result.providerResponse.ifBlank { "No provider response was returned." },
            fontFamily = FontFamily.Monospace,
            fontSize = 10.sp,
            lineHeight = 14.sp,
            maxLines = 8,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            "Correlated account logs",
            color = SilkscreenGray,
            style = MaterialTheme.typography.labelMedium,
        )
        Surface(
            color = DeepGraphite,
            contentColor = RecorderPaper,
            shape = MaterialTheme.shapes.extraSmall,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                text = result.correlatedLogs.takeIf(List<String>::isNotEmpty)
                    ?.joinToString("\n")
                    ?: "No correlated log lines were captured.",
                modifier = Modifier.padding(7.dp),
                color = ShellLabel,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                lineHeight = 14.sp,
                maxLines = 8,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun FolderDialog(
    target: AccountTarget?,
    busy: Boolean,
    onDismiss: () -> Unit,
    onCreate: (String) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Create folder", target?.provider) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(target?.displayName ?: "No account selected", fontFamily = FontFamily.Monospace)
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Folder name") },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onCreate(name.trim()) },
                enabled = name.isNotBlank() && target != null && !busy,
            ) { Text("Create folder") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun GenerateMessageDialog(
    accounts: List<AccountInfo>,
    selectedTarget: AccountTarget?,
    selectedFolderId: String?,
    selectedTargetFolders: List<FolderInfo>,
    busy: Boolean,
    onDismiss: () -> Unit,
    onGenerate: (GenerateMessageRequest) -> Unit,
) {
    val readyAccounts = accounts.filter {
        it.credentialReadiness == CredentialReadiness.READY
    }
    val initialTarget = selectedTarget
        ?.takeIf { selected -> readyAccounts.any { it.target() == selected } }
        ?: readyAccounts.firstOrNull()?.target()
    var target by remember { mutableStateOf(initialTarget) }
    var sourceType by remember { mutableStateOf(MessageSourceType.TEXT) }
    var deliveryMode by remember { mutableStateOf(MessageDeliveryMode.DIRECT_APPEND) }
    var subject by remember { mutableStateOf("Dashboard reproduction") }
    var fromAddress by remember { mutableStateOf("debugger@local.test") }
    var content by remember { mutableStateOf("") }
    var seed by remember { mutableStateOf("") }
    var folderId by remember { mutableStateOf(selectedFolderId) }
    val parsedSeed = seed.toLongOrNull()
    val needsContent = sourceType == MessageSourceType.EML || sourceType == MessageSourceType.TEXT
    val seedValid = seed.isBlank() || parsedSeed != null
    val targetAccount = accounts.firstOrNull { it.target() == target }
    val smtpAvailable = MailProtocol.SMTP in targetAccount?.protocols.orEmpty()
    val usesDirectAppend = deliveryMode == MessageDeliveryMode.DIRECT_APPEND
    val canGenerate = target != null &&
        targetAccount?.credentialReadiness == CredentialReadiness.READY &&
        (!needsContent || content.isNotBlank()) && seedValid &&
        (usesDirectAppend || smtpAvailable) && !busy
    val targetUsesLoadedFolders = target == selectedTarget

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Create test message", target?.provider) },
        text = {
            Column(
                modifier = Modifier
                    .widthIn(min = 320.dp, max = 700.dp)
                    .heightIn(max = 640.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    "Target account channel",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                accounts.forEach { account ->
                    ProviderTargetChoice(
                        account = account,
                        selected = target == account.target(),
                        enabled = account.credentialReadiness == CredentialReadiness.READY,
                        onClick = {
                            target = account.target()
                            if (MailProtocol.SMTP !in account.protocols) {
                                deliveryMode = MessageDeliveryMode.DIRECT_APPEND
                            }
                            folderId = if (account.target() == selectedTarget) selectedFolderId else null
                        },
                    )
                }
                Text("Path", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    DeliveryPathChoice(
                        mode = MessageDeliveryMode.DIRECT_APPEND,
                        selected = usesDirectAppend,
                        enabled = targetAccount?.credentialReadiness == CredentialReadiness.READY,
                        onClick = { deliveryMode = MessageDeliveryMode.DIRECT_APPEND },
                    )
                    DeliveryPathChoice(
                        mode = MessageDeliveryMode.SMTP_DELIVERY,
                        selected = deliveryMode == MessageDeliveryMode.SMTP_DELIVERY,
                        enabled = smtpAvailable,
                        onClick = { deliveryMode = MessageDeliveryMode.SMTP_DELIVERY },
                    )
                }
                Text("Source", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    MessageSourceType.entries.forEach { candidate ->
                        SelectionButton(
                            label = candidate.sourceLabel(),
                            selected = sourceType == candidate,
                            onClick = { sourceType = candidate },
                        )
                    }
                }
                if (!usesDirectAppend) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(PanelFog)
                            .border(1.dp, PanelFogDark)
                            .padding(horizontal = 10.dp, vertical = 8.dp),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        Text("Destination folder", fontWeight = FontWeight.SemiBold)
                        Text("Inbox · fixed by SMTP delivery", fontFamily = FontFamily.Monospace)
                        Text(
                            "SMTP submits the message to the provider, which delivers it to Inbox.",
                            color = SilkscreenGray,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                } else if (targetUsesLoadedFolders && selectedTargetFolders.isNotEmpty()) {
                    Text("Destination folder", fontWeight = FontWeight.SemiBold)
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        selectedTargetFolders.forEach { folder ->
                            SelectionButton(
                                label = folder.name,
                                selected = folderId == folder.id,
                                onClick = { folderId = folder.id },
                                compact = true,
                            )
                        }
                    }
                } else {
                    Text(
                        "The provider Inbox is used when the target mailbox is not open.",
                        color = SilkscreenGray,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (sourceType != MessageSourceType.EML) {
                    OutlinedTextField(
                        value = subject,
                        onValueChange = { subject = it },
                        label = { Text("Subject (optional for random)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = fromAddress,
                        onValueChange = { fromAddress = it },
                        label = { Text("From address") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                when (sourceType) {
                    MessageSourceType.EML -> OutlinedTextField(
                        value = content,
                        onValueChange = { content = it },
                        label = { Text("Raw .eml / RFC 5322 content") },
                        supportingText = { Text("Paste the complete headers and body.") },
                        minLines = 10,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    MessageSourceType.TEXT -> OutlinedTextField(
                        value = content,
                        onValueChange = { content = it },
                        label = { Text("Plain-text body") },
                        minLines = 7,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    MessageSourceType.RANDOM -> OutlinedTextField(
                        value = seed,
                        onValueChange = { seed = it },
                        label = { Text("Deterministic seed (optional)") },
                        singleLine = true,
                        isError = !seedValid,
                        supportingText = {
                            Text(if (seedValid) "Reuse a seed to reproduce the same fixture data." else "Seed must be a whole number.")
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val resolvedTarget = requireNotNull(target)
                    onGenerate(
                        GenerateMessageRequest(
                            targetAccount = resolvedTarget.address,
                            provider = resolvedTarget.provider,
                            providerAccountId = resolvedTarget.providerAccountId,
                            sourceType = sourceType,
                            deliveryMode = deliveryMode,
                            content = content.takeIf { sourceType != MessageSourceType.RANDOM },
                            subject = subject.takeIf(String::isNotBlank),
                            seed = parsedSeed,
                            folderId = folderId.takeIf { usesDirectAppend && targetUsesLoadedFolders },
                            count = 1,
                            fromAddress = fromAddress.takeIf(String::isNotBlank),
                        ),
                    )
                },
                enabled = canGenerate,
            ) {
                Text(
                    when (deliveryMode) {
                        MessageDeliveryMode.DIRECT_APPEND -> "Append message"
                        MessageDeliveryMode.SMTP_DELIVERY -> "Send via SMTP"
                    },
                )
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun DeliveryPathChoice(
    mode: MessageDeliveryMode,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val label = when (mode) {
        MessageDeliveryMode.DIRECT_APPEND -> "Direct append"
        MessageDeliveryMode.SMTP_DELIVERY -> "SMTP delivery"
    }
    val description = when (mode) {
        MessageDeliveryMode.DIRECT_APPEND ->
            "Write directly into the mailbox. You can choose Inbox or another loaded folder."
        MessageDeliveryMode.SMTP_DELIVERY -> if (enabled) {
            "Send through this provider's SMTP service. Provider delivery always targets Inbox."
        } else {
            "Unavailable for this account because SMTP is not enabled."
        }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (selected) PanelFog else RecorderPaper)
            .border(1.dp, if (selected) InstrumentGraphite else PanelFogDark)
            .selectable(
                selected = selected,
                enabled = enabled,
                role = Role.RadioButton,
                onClick = onClick,
            )
            .padding(horizontal = 8.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        RadioButton(
            selected = selected,
            onClick = null,
            enabled = enabled,
        )
        Column(Modifier.weight(1f)) {
            Text(
                label,
                color = if (enabled) InstrumentGraphite else SilkscreenGray,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                description,
                color = SilkscreenGray,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun ProviderTargetChoice(
    account: AccountInfo,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (selected) account.provider.channelWash() else RecorderPaper)
            .border(1.dp, if (selected) account.provider.channelColor() else PanelFogDark)
            .clickable(enabled = enabled, onClick = onClick)
            .semantics {
                this.selected = selected
                role = Role.Button
            },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .width(5.dp)
                .height(48.dp)
                .background(account.provider.channelColor()),
        )
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 10.dp, vertical = 6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(account.address, modifier = Modifier.weight(1f), fontFamily = FontFamily.Monospace)
                ReadinessBadge(account.credentialReadiness)
            }
            Text(
                "${account.provider.displayName()} · ${account.protocols.joinToString(" + ") { it.name }}",
                color = SilkscreenGray,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun ConfirmDialog(
    title: String,
    body: String,
    confirmLabel: String,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            Button(
                onClick = onConfirm,
                enabled = !busy,
                colors = ButtonDefaults.buttonColors(
                    containerColor = RecorderCursorRed,
                    contentColor = Color.White,
                ),
            ) { Text(confirmLabel) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun DialogTitle(title: String, provider: Provider?) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        provider?.let {
            Box(
                Modifier
                    .width(5.dp)
                    .height(28.dp)
                    .background(it.channelColor()),
            )
        }
        Text(title)
    }
}

@Composable
private fun ProviderSelectionButton(
    provider: Provider,
    selected: Boolean,
    onClick: () -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        colors = ButtonDefaults.outlinedButtonColors(
            containerColor = if (selected) provider.channelWash() else RecorderPaper,
            contentColor = InstrumentGraphite,
        ),
        border = BorderStroke(1.dp, provider.channelColor()),
        modifier = Modifier.semantics { this.selected = selected },
    ) {
        Text(provider.displayName())
    }
}

private fun Provider.channelColor(): Color = when (this) {
    Provider.DOVECOT -> DovecotCyan
    Provider.STALWART -> StalwartAmber
}

private fun Provider.channelWash(): Color = when (this) {
    Provider.DOVECOT -> DovecotWash
    Provider.STALWART -> StalwartWash
}

private val DOVECOT_FIXED_PROTOCOLS = listOf(
    MailProtocol.IMAP,
    MailProtocol.POP3,
    MailProtocol.SMTP,
)

private val STALWART_SELECTABLE_PROTOCOLS = listOf(
    MailProtocol.JMAP,
    MailProtocol.SMTP,
)

private fun Provider.creationProtocols(selected: Set<MailProtocol>): List<MailProtocol> = when (this) {
    Provider.DOVECOT -> DOVECOT_FIXED_PROTOCOLS
    Provider.STALWART -> STALWART_SELECTABLE_PROTOCOLS.filter(selected::contains)
}

private fun AccountInfo.supportedAuthenticationProtocols(): List<AuthenticationProtocol> = when (provider) {
    Provider.DOVECOT -> buildList {
        if (MailProtocol.IMAP in protocols) add(AuthenticationProtocol.IMAP)
        if (MailProtocol.POP3 in protocols) add(AuthenticationProtocol.POP3)
        if (MailProtocol.SMTP in protocols) add(AuthenticationProtocol.SMTP)
        if (MailProtocol.IMAP in protocols) add(AuthenticationProtocol.OAUTH_IMAP)
        if (MailProtocol.SMTP in protocols) add(AuthenticationProtocol.OAUTH_SMTP)
    }
    Provider.STALWART -> buildList {
        if (MailProtocol.JMAP in protocols) add(AuthenticationProtocol.JMAP)
        if (MailProtocol.SMTP in protocols) add(AuthenticationProtocol.SMTP)
    }
}

private fun AuthenticationProtocol.displayName(): String = when (this) {
    AuthenticationProtocol.IMAP -> "IMAP password"
    AuthenticationProtocol.POP3 -> "POP3 password"
    AuthenticationProtocol.SMTP -> "SMTP password"
    AuthenticationProtocol.JMAP -> "JMAP password"
    AuthenticationProtocol.OAUTH_IMAP -> "IMAP OAuth"
    AuthenticationProtocol.OAUTH_SMTP -> "SMTP OAuth"
}

private fun AuthenticationProtocol.requiresOverride(): Boolean = when (this) {
    AuthenticationProtocol.OAUTH_IMAP,
    AuthenticationProtocol.OAUTH_SMTP,
    -> true
    else -> false
}

private fun CredentialReadiness.displayName(): String = when (this) {
    CredentialReadiness.READY -> "Ready"
    CredentialReadiness.PASSWORD_REQUIRED -> "Password required"
    CredentialReadiness.AUTHENTICATION_FAILED -> "Authentication failed"
    CredentialReadiness.PROVIDER_UNAVAILABLE -> "Provider unavailable"
}

private fun CredentialReadiness.defaultMessage(): String = when (this) {
    CredentialReadiness.READY -> "Ordinary account authentication is ready."
    CredentialReadiness.PASSWORD_REQUIRED ->
        "Supply and verify the existing password, or reset it to a known local test value."
    CredentialReadiness.AUTHENTICATION_FAILED ->
        "The remembered password failed ordinary account authentication."
    CredentialReadiness.PROVIDER_UNAVAILABLE ->
        "Credential readiness could not be verified because this provider is unavailable."
}

private fun MailProtocol.description(): String = when (this) {
    MailProtocol.IMAP -> "Mailbox access through Dovecot IMAP"
    MailProtocol.POP3 -> "Dovecot POP3 retrieval"
    MailProtocol.JMAP -> "Stalwart JMAP mailbox operations"
    MailProtocol.SMTP -> "Message submission and delivery"
}

private fun MessageSourceType.sourceLabel(): String = when (this) {
    MessageSourceType.EML -> "Raw EML"
    MessageSourceType.TEXT -> "Authored text"
    MessageSourceType.RANDOM -> "Random fixture"
}

private fun LogService.displayName(): String = when (this) {
    LogService.ALL -> "All"
    LogService.DOVECOT -> "Dovecot"
    LogService.POSTFIX -> "Postfix"
    LogService.OAUTH2 -> "OAuth2 mock"
    LogService.STALWART -> "Stalwart"
}
