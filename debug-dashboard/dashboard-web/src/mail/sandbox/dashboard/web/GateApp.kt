/*
THESIS: This is the minimal Gate 0A extension of the established Evidence Split world, not a new visual direction.
OWN-WORLD: Mail Flight Recorder places precise operational evidence on recorder paper inside a graphite shell.
STORY: A developer verifies the Kotlin/Wasm route, reducer, controls, transport placeholders, and resource pipeline.
FIRST VIEWPORT: Product identity, route controls, live gate state, and the proof marker stay immediately visible.
FORM: Flat rails, keylines, tonal zones, low-radius Material controls, readable contrast, and restrained motion.
*/
package mail.sandbox.dashboard.web

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Shapes
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlin.js.ExperimentalWasmJsInterop
import kotlin.js.JsString
import kotlin.js.unsafeCast
import kotlinx.browser.window
import kotlinx.coroutines.await
import kotlinx.serialization.json.Json
import mail.sandbox.dashboard.contract.GateEvent
import mail.sandbox.dashboard.contract.GateProbe
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
private val RecorderPaper = Color(0xFFF4F2E8)
private val PanelFog = Color(0xFFE8E7DE)
private val SilkscreenGray = Color(0xFF526064)
private val RecorderCursorRed = Color(0xFFC7473A)

private val GateColorScheme = lightColorScheme(
    primary = InstrumentGraphite,
    onPrimary = RecorderPaper,
    background = InstrumentGraphite,
    onBackground = RecorderPaper,
    surface = RecorderPaper,
    onSurface = InstrumentGraphite,
    surfaceVariant = PanelFog,
    onSurfaceVariant = SilkscreenGray,
    error = RecorderCursorRed,
    onError = Color.White,
)

private val GateShapes = Shapes(
    extraSmall = RoundedCornerShape(2.dp),
    small = RoundedCornerShape(2.dp),
    medium = RoundedCornerShape(3.dp),
    large = RoundedCornerShape(4.dp),
    extraLarge = RoundedCornerShape(4.dp),
)

@OptIn(ExperimentalWasmJsInterop::class)
@Composable
internal fun GateApp(modifier: Modifier = Modifier) {
    val initialRoute = GateRoute.fromPath(window.location.pathname) ?: GateRoute.Overview
    val stateHolder = remember { mutableStateOf(GateState(route = initialRoute)) }
    val state = stateHolder.value
    val resourceMarkerHolder = remember { mutableStateOf("GATE_RESOURCE: loading") }
    val dispatch: (GateAction) -> Unit = { action ->
        stateHolder.value = reduceGateState(stateHolder.value, action)
    }

    LaunchedEffect(Unit) {
        resourceMarkerHolder.value =
            Res.readBytes("files/gate-proof.txt").decodeToString().trim()
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
            dispatch(
                GateAction.ApiProbeFailed(
                    failure.message ?: "probe failed",
                ),
            )
        }
    }

    DisposableEffect(Unit) {
        val popStateListener: (Event) -> Unit = {
            dispatch(GateAction.RouteSelected(window.location.pathname))
        }
        window.addEventListener("popstate", popStateListener)
        onDispose {
            window.removeEventListener("popstate", popStateListener)
        }
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

        eventSource.onopen = {
            dispatch(GateAction.SseConnected)
        }
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
        colorScheme = GateColorScheme,
        shapes = GateShapes,
    ) {
        GateSurface(
            state = state,
            resourceMarker = resourceMarkerHolder.value,
            onAction = dispatch,
            onRouteSelected = { route ->
                if (route != state.route) {
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
    val data = event.data?.unsafeCast<JsString>()?.toString()
        ?: return@runCatching null
    Json.decodeFromString<GateEvent>(data)
}.getOrNull()

@Composable
private fun GateSurface(
    state: GateState,
    resourceMarker: String,
    onAction: (GateAction) -> Unit,
    onRouteSelected: (GateRoute) -> Unit,
    modifier: Modifier = Modifier,
) {
    val incrementInteractionSource = remember { MutableInteractionSource() }
    val incrementFocused by incrementInteractionSource.collectIsFocusedAsState()

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(InstrumentGraphite),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "Local mail sandbox · Gate 0A",
                color = RecorderPaper,
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier
                    .widthIn(max = 920.dp)
                    .fillMaxWidth(),
            )
            Spacer(Modifier.height(12.dp))
            Surface(
                modifier = Modifier
                    .widthIn(max = 920.dp)
                    .fillMaxWidth(),
                color = RecorderPaper,
                contentColor = InstrumentGraphite,
                shape = MaterialTheme.shapes.large,
                border = BorderStroke(1.dp, SilkscreenGray),
            ) {
                Column {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp, vertical = 20.dp),
                    ) {
                        Text(
                            text = "Mail Flight Recorder",
                            style = MaterialTheme.typography.headlineMedium,
                            modifier = Modifier.semantics { heading() },
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Kotlin / Wasm feasibility gate",
                            color = SilkscreenGray,
                            style = MaterialTheme.typography.bodyLarge,
                        )
                    }

                    HorizontalDivider(color = SilkscreenGray)

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(PanelFog)
                            .padding(horizontal = 24.dp, vertical = 18.dp),
                    ) {
                        Text(
                            text = "Gate controls",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "Selected route: ${state.route.path}",
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(
                                onClick = { onRouteSelected(GateRoute.Overview) },
                                border = BorderStroke(1.dp, InstrumentGraphite),
                                modifier = Modifier.semantics {
                                    selected = state.route == GateRoute.Overview
                                },
                            ) {
                                Text("Overview")
                            }
                            OutlinedButton(
                                onClick = { onRouteSelected(GateRoute.Details) },
                                border = BorderStroke(1.dp, InstrumentGraphite),
                                modifier = Modifier.semantics {
                                    selected = state.route == GateRoute.Details
                                },
                            ) {
                                Text("Gate details")
                            }
                        }
                        Spacer(Modifier.height(12.dp))
                        Column(
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Button(
                                onClick = { onAction(GateAction.IncrementProof) },
                                interactionSource = incrementInteractionSource,
                                modifier = if (incrementFocused) {
                                    Modifier.border(
                                        width = 3.dp,
                                        color = RecorderCursorRed,
                                        shape = MaterialTheme.shapes.small,
                                    )
                                } else {
                                    Modifier
                                },
                            ) {
                                Text("Increment proof")
                            }
                            Text(
                                text = "Activation count: ${state.activationCount}",
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.semantics {
                                    liveRegion = LiveRegionMode.Polite
                                },
                            )
                            Text(
                                text = if (incrementFocused) {
                                    "Keyboard focus: increment proof"
                                } else {
                                    "Keyboard focus: none"
                                },
                                color = if (incrementFocused) {
                                    RecorderCursorRed
                                } else {
                                    SilkscreenGray
                                },
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }

                    HorizontalDivider(color = SilkscreenGray)

                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp, vertical = 18.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = "Transport state",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        GateStatusText("JSON API: ${state.apiProbeStatus.name.lowercase()}")
                        GateStatusText("API message: ${state.apiProbeMessage ?: "pending"}")
                        GateStatusText("SSE sequence: ${state.sseSequence ?: "pending"}")
                        GateStatusText(
                            "Reconnect status: ${state.sseConnectionStatus.name.lowercase()}",
                        )
                        GateStatusText("SSE sync: ${state.sseSyncStatus.name.lowercase()}")
                    }

                    HorizontalDivider(color = SilkscreenGray)

                    Text(
                        text = resourceMarker,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun GateStatusText(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        color = SilkscreenGray,
        style = MaterialTheme.typography.bodyMedium,
        modifier = modifier
            .fillMaxWidth()
            .semantics {
                liveRegion = LiveRegionMode.Polite
            },
    )
}
