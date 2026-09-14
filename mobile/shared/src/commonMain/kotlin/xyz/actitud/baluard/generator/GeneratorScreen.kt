package xyz.actitud.baluard.generator

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.SliderDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
import xyz.actitud.baluard.i18n.t
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import xyz.actitud.baluard.ui.components.BaluardCard
import xyz.actitud.baluard.ui.components.BaluardPrimaryButton
import xyz.actitud.baluard.ui.components.BaluardTopBar
import xyz.actitud.baluard.ui.components.CopiedBadge
import xyz.actitud.baluard.ui.components.SectionCard
import xyz.actitud.baluard.ui.components.ToggleRow
import xyz.actitud.baluard.ui.components.rememberCopied

/**
 * Password + passphrase generator styled after Baluard design language.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GeneratorScreen(viewModel: GeneratorViewModel, onBack: () -> Unit = {}) {
    val state by viewModel.state.collectAsState()
    val scope = rememberCoroutineScope()
    val copied = rememberCopied()
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            BaluardTopBar(
                title = t("generator.title"),
                onBack = onBack,
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Mode Selector
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                SegmentedButton(
                    selected = state.mode == GeneratorMode.PASSWORD,
                    onClick = { viewModel.setMode(GeneratorMode.PASSWORD) },
                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                    colors = SegmentedButtonDefaults.colors(
                        activeContainerColor = MaterialTheme.colorScheme.primary,
                        activeContentColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                    label = {
                        Text(
                            t("generator.password"),
                            style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold),
                        )
                    },
                )
                SegmentedButton(
                    selected = state.mode == GeneratorMode.PASSPHRASE,
                    onClick = { viewModel.setMode(GeneratorMode.PASSPHRASE) },
                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                    colors = SegmentedButtonDefaults.colors(
                        activeContainerColor = MaterialTheme.colorScheme.primary,
                        activeContentColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                    label = {
                        Text(
                            t("generator.passphrase"),
                            style = MaterialTheme.typography.labelLarge.copy(fontWeight = FontWeight.Bold),
                        )
                    },
                )
            }

            // Output Display Card
            BaluardCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = t("generator.result").uppercase(),
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontWeight = FontWeight.ExtraBold,
                            letterSpacing = 0.5.sp,
                        ),
                        color = MaterialTheme.colorScheme.primary,
                    )
                    CopiedBadge(visible = copied.visible)
                }

                Spacer(Modifier.height(8.dp))

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surface)
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f), RoundedCornerShape(12.dp))
                        .clickable {
                            state.result?.let {
                                copied.copy(it)
                            }
                        }
                        .padding(14.dp),
                ) {
                    AnimatedContent(
                        targetState = state.result,
                        transitionSpec = {
                            fadeIn(animationSpec = tween(150, easing = FastOutSlowInEasing))
                                .togetherWith(fadeOut(animationSpec = tween(100)))
                        },
                        label = "GeneratedResultTransition",
                    ) { res ->
                        Text(
                            text = res ?: "—",
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontWeight = FontWeight.Bold,
                                letterSpacing = 1.sp,
                            ),
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }

                Spacer(Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    BaluardPrimaryButton(
                        text = t("generator.generate"),
                        onClick = { scope.launch { viewModel.generate() } },
                        leadingIcon = Icons.Default.Refresh,
                        modifier = Modifier.weight(1f),
                    )

                    IconButton(
                        onClick = {
                            state.result?.let {
                                copied.copy(it)
                            }
                        },
                        modifier = Modifier
                            .size(50.dp)
                            .clip(RoundedCornerShape(12.dp))
                            .background(MaterialTheme.colorScheme.surface)
                            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp)),
                    ) {
                        Icon(
                            imageVector = Icons.Default.ContentCopy,
                            contentDescription = t("detail.copy"),
                            tint = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }
            }

            // Controls Section Card with smooth AnimatedContent
            AnimatedContent(
                targetState = state.mode,
                transitionSpec = {
                    fadeIn(animationSpec = tween(200, easing = FastOutSlowInEasing))
                        .togetherWith(fadeOut(animationSpec = tween(150)))
                },
                label = "GeneratorModeControlsTransition",
            ) { mode ->
                if (mode == GeneratorMode.PASSWORD) {
                    SectionCard(title = t("generator.passwordSettings")) {
                        PasswordControls(state, viewModel)
                    }
                } else {
                    SectionCard(title = t("generator.passphraseSettings")) {
                        PassphraseControls(state, viewModel)
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun PasswordControls(state: GeneratorUiState, viewModel: GeneratorViewModel) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = t("generator.length"),
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
        )
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f))
                .padding(horizontal = 8.dp, vertical = 2.dp),
        ) {
            Text(
                text = t("generator.chars", state.length),
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }

    Slider(
        value = state.length.toFloat(),
        onValueChange = { viewModel.setLength(it.toInt()) },
        valueRange = 8f..64f,
        steps = 0,
        colors = SliderDefaults.colors(
            thumbColor = MaterialTheme.colorScheme.primary,
            activeTrackColor = MaterialTheme.colorScheme.primary,
        ),
    )

    androidx.compose.material3.HorizontalDivider(
        modifier = Modifier.padding(vertical = 6.dp),
        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
    )

    ToggleRow(t("generator.upper"), state.upper) { viewModel.setUpper(it) }
    ToggleRow(t("generator.numbers"), state.numbers) { viewModel.setNumbers(it) }
    ToggleRow(t("generator.symbols"), state.symbols) { viewModel.setSymbols(it) }
}

@Composable
private fun PassphraseControls(state: GeneratorUiState, viewModel: GeneratorViewModel) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = t("generator.wordCount"),
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
        )
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f))
                .padding(horizontal = 8.dp, vertical = 2.dp),
        ) {
            Text(
                text = t("generator.words", state.wordCount),
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }

    Slider(
        value = state.wordCount.toFloat(),
        onValueChange = { viewModel.setWordCount(it.toInt()) },
        valueRange = 3f..10f,
        steps = 6,
        colors = SliderDefaults.colors(
            thumbColor = MaterialTheme.colorScheme.primary,
            activeTrackColor = MaterialTheme.colorScheme.primary,
        ),
    )

    OutlinedTextField(
        value = state.separator,
        onValueChange = { viewModel.setSeparator(it) },
        label = { Text(t("generator.separator")) },
        singleLine = true,
        shape = RoundedCornerShape(10.dp),
        colors = OutlinedTextFieldDefaults.colors(
            focusedContainerColor = MaterialTheme.colorScheme.surface,
            unfocusedContainerColor = MaterialTheme.colorScheme.surface,
            focusedBorderColor = MaterialTheme.colorScheme.primary,
            unfocusedBorderColor = MaterialTheme.colorScheme.outlineVariant,
        ),
        modifier = Modifier.fillMaxWidth(),
    )

    Spacer(Modifier.height(8.dp))

    ToggleRow(t("generator.capitalize"), state.ppUpper) { viewModel.setPpUpper(it) }
    ToggleRow(t("generator.insertNumber"), state.ppNumber) { viewModel.setPpNumber(it) }
    ToggleRow(t("generator.insertSymbol"), state.ppSymbol) { viewModel.setPpSymbol(it) }
}

