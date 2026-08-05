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
    Trace("Trace"),
}

private enum class TraceMode(val label: String) {
    Account("Account trace"),
    Server("Server logs"),
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
    var passwordOpen by remember { mutableStateOf(false) }
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
                            onPassword = { passwordOpen = true },
                            onDelete = { accountDeleteOpen = true },
                            onRefresh = { scope.launch { controller.refreshWorkspace() } },
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
                                        .weight(0.58f)
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
                                        .weight(0.42f)
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
                                onPassword = { passwordOpen = true },
                                onDelete = { accountDeleteOpen = true },
                                onRefresh = { scope.launch { controller.refreshWorkspace() } },
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
    if (passwordOpen) {
        PasswordDialog(
            target = controller.selectedTarget,
            busy = controller.busyLabel != null,
            onDismiss = { passwordOpen = false },
            onSubmit = { password ->
                passwordOpen = false
                scope.launch { controller.changePassword(password) }
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
                enabled = controller.accounts.isNotEmpty() && controller.busyLabel == null,
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
                .height(44.dp)
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
                .height(44.dp)
                .semantics { this.selected = selected },
        ) {
            Column(Modifier.fillMaxWidth()) {
                Text(account.provider.displayName(), fontWeight = FontWeight.SemiBold)
                Text(
                    account.protocols.joinToString(" + ") { it.name },
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    maxLines = 1,
                )
            }
        }
    }
}

@Composable
private fun AccountHeader(
    controller: DashboardController,
    onPassword: () -> Unit,
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
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    Modifier
                        .width(6.dp)
                        .height(66.dp)
                        .background(account.provider.channelColor()),
                )
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(horizontal = 12.dp, vertical = 9.dp),
                ) {
                    Text(
                        account.address,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        "${account.provider.displayName()} · ${account.protocols.joinToString(" / ") { it.name }}",
                        color = SilkscreenGray,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                    )
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
                        onClick = onPassword,
                        enabled = controller.busyLabel == null,
                    ) { Text("Change password") }
                    TextButton(
                        onClick = onDelete,
                        enabled = controller.busyLabel == null,
                        colors = ButtonDefaults.textButtonColors(contentColor = RecorderCursorRed),
                    ) { Text("Delete account") }
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
            Text(
                account.provider.displayName(),
                color = SilkscreenGray,
                style = MaterialTheme.typography.bodySmall,
            )
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
                enabled = controller.selectedTarget != null && controller.busyLabel == null,
            ) { Text("New") }
        },
    ) {
        when {
            controller.selectedTarget == null -> EmptyState("No account selected", "Choose an account channel first.")
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
                enabled = !busy,
                onClick = {
                    onAction(
                        if (message.isRead) MessageAction.MARK_UNREAD else MessageAction.MARK_READ,
                        null,
                    )
                },
            )
            OperationButton(
                label = if (message.isFlagged) "Unflag" else "Flag",
                enabled = !busy,
                onClick = {
                    onAction(
                        if (message.isFlagged) MessageAction.UNFLAG else MessageAction.FLAG,
                        null,
                    )
                },
            )
            OperationButton("Trash", enabled = !busy) {
                onAction(MessageAction.TRASH, null)
            }
            TextButton(
                onClick = onDelete,
                enabled = !busy,
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
                    enabled = selectedDestination != null && !busy,
                ) { onAction(MessageAction.MOVE, selectedDestination) }
                OperationButton(
                    "Copy",
                    enabled = selectedDestination != null && !busy,
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
) {
    OutlinedButton(
        onClick = onClick,
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
        mutableStateOf(setOf(MailProtocol.IMAP, MailProtocol.SMTP))
    }
    val allowed = provider.allowedProtocols()
    val canCreate = address.isNotBlank() && password.isNotBlank() && protocols.isNotEmpty() && !busy

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
                                protocols = candidate.defaultProtocols()
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
                Text(
                    "Choose the protocols this account is meant to exercise. The dashboard " +
                        "uses this profile for actions and guidance; provider-internal mailbox " +
                        "access may remain enabled for diagnostics.",
                    color = SilkscreenGray,
                    style = MaterialTheme.typography.bodySmall,
                )
                allowed.forEach { protocol ->
                    ProtocolToggle(
                        protocol = protocol,
                        checked = protocol in protocols,
                        onCheckedChange = { checked ->
                            protocols = if (checked) protocols + protocol else protocols - protocol
                        },
                    )
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
                            protocols = allowed.filter(protocols::contains),
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
    busy: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { DialogTitle("Change account password", target?.provider) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(target?.displayName ?: "No account selected", fontFamily = FontFamily.Monospace)
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("New password") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onSubmit(password) },
                enabled = password.isNotBlank() && target != null && !busy,
            ) { Text("Change password") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
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
    var target by remember { mutableStateOf(selectedTarget ?: accounts.firstOrNull()?.target()) }
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
                        enabled = target != null,
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
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(if (selected) account.provider.channelWash() else RecorderPaper)
            .border(1.dp, if (selected) account.provider.channelColor() else PanelFogDark)
            .clickable(onClick = onClick)
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
        Column(Modifier.padding(horizontal = 10.dp, vertical = 6.dp)) {
            Text(account.address, fontFamily = FontFamily.Monospace)
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

private fun Provider.allowedProtocols(): List<MailProtocol> = when (this) {
    Provider.DOVECOT -> listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP)
    Provider.STALWART -> listOf(MailProtocol.JMAP, MailProtocol.SMTP)
}

private fun Provider.defaultProtocols(): Set<MailProtocol> = when (this) {
    Provider.DOVECOT -> setOf(MailProtocol.IMAP, MailProtocol.SMTP)
    Provider.STALWART -> setOf(MailProtocol.JMAP, MailProtocol.SMTP)
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
