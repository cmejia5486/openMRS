package com.chartlite.app.ui.screens

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChildCare
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FavoriteBorder
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.LocalHospital
import androidx.compose.material.icons.filled.MedicalServices
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.protocols.ClinicalProtocol
import com.chartlite.app.protocols.ProtocolAlternative
import com.chartlite.app.protocols.ProtocolMedication
import com.chartlite.app.protocols.ProtocolStep
import com.chartlite.app.ui.theme.AccentOrange
import com.chartlite.app.ui.theme.AlertRed
import com.chartlite.app.ui.theme.AlertRedSurface
import com.chartlite.app.ui.theme.BrandGreen
import com.chartlite.app.ui.theme.BrandGreenDark
import com.chartlite.app.ui.theme.BrandGreenSurface
import com.chartlite.app.ui.theme.InfoBlue
import com.chartlite.app.ui.theme.InfoBlueSurface
import com.chartlite.app.ui.theme.Neutral100
import com.chartlite.app.ui.theme.Neutral200
import com.chartlite.app.ui.theme.Neutral500
import com.chartlite.app.ui.theme.WarningAmber
import com.chartlite.app.ui.theme.WarningAmberSurface
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R

private data class ProtocolCategoryVisual(
    val icon: ImageVector,
    val accent: Color,
    val surface: Color
)

private data class StepSectionSpec(
    val title: String,
    val icon: ImageVector,
    val accent: Color,
    val surface: Color,
    val items: List<String>
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ClinicalProtocolScreen(
    preSelectedIcd10: String? = null,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val engine = app.protocolEngine

    var searchQuery by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableStateOf<String?>(null) }
    var selectedProtocol by remember { mutableStateOf<ClinicalProtocol?>(null) }
    var expandedStepId by remember { mutableStateOf<String?>(null) }

    val allProtocols = remember { engine.getAllProtocols() }
    val categories = remember(allProtocols) { engine.getCategories() }
    val emergencyCount = remember(allProtocols) {
        allProtocols.count { it.urgency.equals("EMERGENCY", ignoreCase = true) }
    }
    val preSelectedProtocols = remember(preSelectedIcd10, allProtocols) {
        preSelectedIcd10?.let { code -> engine.findByICD10(code) } ?: emptyList()
    }

    LaunchedEffect(preSelectedProtocols) {
        if (preSelectedProtocols.size == 1 && selectedProtocol == null) {
            selectedProtocol = preSelectedProtocols.first()
        }
    }

    val displayedProtocols = remember(allProtocols, searchQuery, selectedCategory) {
        filterProtocols(
            protocols = allProtocols,
            searchQuery = searchQuery,
            selectedCategory = selectedCategory
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = selectedProtocol?.name ?: stringResource(R.string.clinical_protocols),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(
                        onClick = {
                            if (selectedProtocol != null) {
                                selectedProtocol = null
                                expandedStepId = null
                            } else {
                                onBack()
                            }
                        }
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.back))
                    }
                }
            )
        }
    ) { padding ->
        if (selectedProtocol == null) {
            ProtocolBrowseView(
                protocols = displayedProtocols,
                allProtocols = allProtocols,
                categories = categories,
                selectedCategory = selectedCategory,
                searchQuery = searchQuery,
                preSelectedIcd10 = preSelectedIcd10,
                preSelectedProtocols = preSelectedProtocols,
                emergencyCount = emergencyCount,
                onSearchChanged = { searchQuery = it },
                onCategorySelected = { category ->
                    selectedCategory = when {
                        category.isBlank() -> null
                        selectedCategory == category -> null
                        else -> category
                    }
                },
                onProtocolSelected = {
                    selectedProtocol = it
                    expandedStepId = null
                },
                modifier = Modifier.padding(padding)
            )
        } else {
            ProtocolDetailView(
                protocol = selectedProtocol ?: return@Scaffold,
                expandedStepId = expandedStepId,
                onStepToggle = { stepId ->
                    expandedStepId = if (expandedStepId == stepId) null else stepId
                },
                modifier = Modifier.padding(padding)
            )
        }
    }
}

@Composable
private fun ProtocolBrowseView(
    protocols: List<ClinicalProtocol>,
    allProtocols: List<ClinicalProtocol>,
    categories: List<String>,
    selectedCategory: String?,
    searchQuery: String,
    preSelectedIcd10: String?,
    preSelectedProtocols: List<ClinicalProtocol>,
    emergencyCount: Int,
    onSearchChanged: (String) -> Unit,
    onCategorySelected: (String) -> Unit,
    onProtocolSelected: (ClinicalProtocol) -> Unit,
    modifier: Modifier = Modifier
) {
    val highlightedIds = remember(preSelectedProtocols) { preSelectedProtocols.map { it.id }.toSet() }
    val matchedProtocolsVisible = preSelectedProtocols.isNotEmpty() &&
        searchQuery.isBlank() &&
        selectedCategory == null
    val libraryProtocols = remember(protocols, highlightedIds, matchedProtocolsVisible) {
        if (matchedProtocolsVisible) {
            protocols.filterNot { it.id in highlightedIds }
        } else {
            protocols
        }
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp)
    ) {
        item {
            ProtocolBrowseHero(
                totalProtocols = allProtocols.size,
                emergencyCount = emergencyCount,
                categoryCount = categories.size,
                preSelectedIcd10 = preSelectedIcd10
            )
        }

        item {
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchChanged,
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text(stringResource(R.string.search_protocols_hint)) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                trailingIcon = {
                    if (searchQuery.isNotBlank()) {
                        IconButton(onClick = { onSearchChanged("") }) {
                            Icon(Icons.Default.Clear, contentDescription = stringResource(R.string.clear_all))
                        }
                    }
                },
                singleLine = true,
                shape = RoundedCornerShape(26.dp)
            )
        }

        item {
            ProtocolCategoryRail(
                categories = categories,
                selectedCategory = selectedCategory,
                protocols = allProtocols,
                onCategorySelected = onCategorySelected
            )
        }

        if (matchedProtocolsVisible) {
            item {
                SectionHeader(
                    eyebrow = "Matched for this encounter",
                    title = "${preSelectedProtocols.size} protocol${if (preSelectedProtocols.size == 1) "" else "s"} linked to $preSelectedIcd10"
                )
            }
            items(preSelectedProtocols, key = { "matched_${it.id}" }) { protocol ->
                ProtocolCard(
                    protocol = protocol,
                    isMatched = true,
                    onClick = { onProtocolSelected(protocol) }
                )
            }
        }

        if (libraryProtocols.isNotEmpty()) {
            item {
                Text(
                    text = when {
                        protocols.isEmpty() && searchQuery.isNotBlank() -> "No matches for \"$searchQuery\""
                        selectedCategory != null -> "$selectedCategory (${libraryProtocols.size})"
                        matchedProtocolsVisible -> "${libraryProtocols.size} more protocols"
                        else -> "All protocols"
                    },
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (libraryProtocols.isEmpty()) {
            item {
                EmptyProtocolState(
                    searchQuery = searchQuery,
                    selectedCategory = selectedCategory
                )
            }
        } else {
            items(libraryProtocols, key = { it.id }) { protocol ->
                ProtocolCard(
                    protocol = protocol,
                    isMatched = false,
                    onClick = { onProtocolSelected(protocol) }
                )
            }
        }
    }
}

@Composable
private fun ProtocolBrowseHero(
    totalProtocols: Int,
    emergencyCount: Int,
    categoryCount: Int,
    preSelectedIcd10: String?
) {
    // Compact stats row instead of large hero banner
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        ProtocolHeroMetric("$totalProtocols", "Protocols", BrandGreenDark, Modifier.weight(1f))
        if (emergencyCount > 0) {
            ProtocolHeroMetric("$emergencyCount", "Emergency", AlertRed, Modifier.weight(1f))
        }
        ProtocolHeroMetric("$categoryCount", "Categories", Neutral500, Modifier.weight(1f))
    }

    if (!preSelectedIcd10.isNullOrBlank()) {
        Spacer(Modifier.height(8.dp))
        Surface(
            color = BrandGreenSurface,
            shape = RoundedCornerShape(8.dp)
        ) {
            Text(
                text = "Linked to $preSelectedIcd10",
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                style = MaterialTheme.typography.labelMedium,
                color = BrandGreenDark,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
private fun ProtocolHeroMetric(
    value: String,
    label: String,
    accent: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        color = accent.copy(alpha = 0.08f),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.titleLarge,
                color = accent,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProtocolCategoryRail(
    categories: List<String>,
    selectedCategory: String?,
    protocols: List<ClinicalProtocol>,
    onCategorySelected: (String) -> Unit
) {
    LazyRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = PaddingValues(end = 8.dp)
    ) {
        item {
            FilterChip(
                selected = selectedCategory == null,
                onClick = { onCategorySelected("") },
                label = { Text("All (${protocols.size})") }
            )
        }
        items(categories, key = { it }) { category ->
            val count = protocols.count { it.category.equals(category, ignoreCase = true) }
            FilterChip(
                selected = selectedCategory == category,
                onClick = { onCategorySelected(category) },
                label = { Text("$category ($count)") }
            )
        }
    }
}

@Composable
private fun ProtocolCard(
    protocol: ClinicalProtocol,
    isMatched: Boolean,
    onClick: () -> Unit
) {
    val isEmergency = protocol.urgency.equals("EMERGENCY", ignoreCase = true)
    val visual = categoryVisual(protocol.category)
    val accent = when {
        isEmergency -> AlertRed
        isMatched -> BrandGreenDark
        else -> visual.accent
    }

    OutlinedCard(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, if (isEmergency) AlertRed.copy(alpha = 0.3f) else Neutral200)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min)
        ) {
            // Accent side bar
            Box(
                modifier = Modifier
                    .width(4.dp)
                    .fillMaxHeight()
                    .background(accent)
            )

            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                // ── Row 1: Badges ──
                Row(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Surface(
                        color = visual.surface,
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            protocol.category,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = visual.accent
                        )
                    }
                    if (isEmergency) {
                        Surface(
                            color = AlertRed,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                "EMERGENCY",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = Color.White
                            )
                        }
                    }
                    if (isMatched) {
                        Surface(
                            color = BrandGreenSurface,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                "Matched",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                color = BrandGreenDark
                            )
                        }
                    }
                    Spacer(Modifier.weight(1f))
                    Text(
                        "${protocol.steps.size} steps",
                        style = MaterialTheme.typography.labelSmall,
                        color = Neutral500
                    )
                }

                // ── Row 2: Protocol name ──
                Text(
                    text = protocol.name,
                    style = MaterialTheme.typography.titleMedium,
                    color = if (isEmergency) AlertRed else MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.SemiBold
                )

                // ── Row 3: First step preview ──
                Text(
                    text = protocolPreview(protocol),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )

                // ── Row 4: ICD codes ──
                Text(
                    text = shortIcdSummary(protocol.icd10Codes),
                    style = MaterialTheme.typography.labelSmall,
                    color = Neutral500
                )
            }
        }
    }
}

@Composable
private fun ProtocolDetailView(
    protocol: ClinicalProtocol,
    expandedStepId: String?,
    onStepToggle: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp)
    ) {
        item {
            ProtocolDetailHeader(protocol = protocol)
        }

        item {
            SectionHeader(
                eyebrow = "Care pathway",
                title = "${protocol.steps.size} ordered steps for bedside execution"
            )
        }

        itemsIndexed(protocol.steps, key = { _, step -> step.id }) { index, step ->
            StepCard(
                step = step,
                stepNumber = index + 1,
                isExpanded = expandedStepId == step.id,
                onToggle = { onStepToggle(step.id) }
            )
        }
    }
}

@Composable
private fun ProtocolDetailHeader(protocol: ClinicalProtocol) {
    val isEmergency = protocol.urgency.equals("EMERGENCY", ignoreCase = true)
    val visual = categoryVisual(protocol.category)
    val dangerSigns = protocol.steps.sumOf { it.redFlags?.size ?: 0 }
    val medications = protocol.steps.sumOf { it.medications?.size ?: 0 }
    val earliestFollowUp = protocol.steps.mapNotNull { it.followUpDays }.minOrNull()
    val headerBrush = if (isEmergency) {
        Brush.linearGradient(colors = listOf(AlertRed, AlertRed.copy(alpha = 0.6f)))
    } else {
        Brush.linearGradient(colors = listOf(visual.accent, BrandGreenDark))
    }

    Card(
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(headerBrush, RoundedCornerShape(28.dp))
                .padding(22.dp)
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ProtocolMetaPill(
                        label = protocol.category,
                        accent = Color.White,
                        surface = Color.White.copy(alpha = 0.16f),
                        icon = visual.icon,
                        textColor = Color.White
                    )
                    if (isEmergency) {
                        ProtocolMetaPill(
                            label = "Emergency",
                            accent = Color.White,
                            surface = Color.White.copy(alpha = 0.16f),
                            icon = Icons.Default.Warning,
                            textColor = Color.White
                        )
                    }
                }

                Text(
                    text = protocol.name,
                    style = MaterialTheme.typography.headlineMedium,
                    color = Color.White,
                    fontWeight = FontWeight.Bold
                )

                Text(
                    text = protocolPreview(protocol),
                    style = MaterialTheme.typography.bodyLarge,
                    color = Color.White.copy(alpha = 0.84f)
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    ProtocolStatPill(
                        label = shortIcdSummary(protocol.icd10Codes),
                        background = Color.White.copy(alpha = 0.14f),
                        textColor = Color.White
                    )
                    ProtocolStatPill(
                        label = formatApplicableTo(protocol.applicableTo),
                        background = Color.White.copy(alpha = 0.14f),
                        textColor = Color.White
                    )
                    ProtocolStatPill(
                        label = "${protocol.steps.size} steps",
                        background = Color.White.copy(alpha = 0.14f),
                        textColor = Color.White
                    )
                    if (dangerSigns > 0) {
                        ProtocolStatPill(
                            label = "$dangerSigns danger signs",
                            background = Color.White.copy(alpha = 0.14f),
                            textColor = Color.White
                        )
                    }
                    if (medications > 0) {
                        ProtocolStatPill(
                            label = "$medications medication lines",
                            background = Color.White.copy(alpha = 0.14f),
                            textColor = Color.White
                        )
                    }
                    if (earliestFollowUp != null) {
                        ProtocolStatPill(
                            label = "Follow up in $earliestFollowUp days",
                            background = Color.White.copy(alpha = 0.14f),
                            textColor = Color.White
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StepCard(
    step: ProtocolStep,
    stepNumber: Int,
    isExpanded: Boolean,
    onToggle: () -> Unit
) {
    val isEmergency = step.urgency.equals("EMERGENCY", ignoreCase = true)
    val overviewSections = buildStepSections(step)
    val accent = if (isEmergency || !step.redFlags.isNullOrEmpty()) AlertRed else BrandGreenDark
    val containerColor = if (isEmergency) AlertRedSurface else Color.White

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle)
            .animateContentSize(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = containerColor),
        border = BorderStroke(1.dp, if (isEmergency) Color.Transparent else Neutral200),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(modifier = Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .background(accent, RoundedCornerShape(12.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = stepNumber.toString(),
                        style = MaterialTheme.typography.titleMedium,
                        color = Color.White,
                        fontWeight = FontWeight.Bold
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (isEmergency) {
                            ProtocolMetaPill(
                                label = "Escalate now",
                                accent = AlertRed,
                                surface = AlertRedSurface,
                                icon = Icons.Default.Warning
                            )
                        } else if (!step.redFlags.isNullOrEmpty()) {
                            ProtocolMetaPill(
                                label = "${step.redFlags.orEmpty().size} danger signs",
                                accent = WarningAmber,
                                surface = WarningAmberSurface,
                                icon = Icons.Default.Warning
                            )
                        }
                        step.followUpDays?.let {
                            ProtocolMetaPill(
                                label = "Follow up $it d",
                                accent = InfoBlue,
                                surface = InfoBlueSurface,
                                icon = Icons.Default.Schedule
                            )
                        }
                    }

                    Text(
                        text = step.title,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = step.instructions,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = if (isExpanded) Int.MAX_VALUE else 3,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                Icon(
                    imageVector = if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (isExpanded) "Collapse" else "Expand",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (isExpanded) {
                overviewSections.forEach { section ->
                    StepSectionCard(section = section)
                }

                if (!step.alternatives.isNullOrEmpty()) {
                    StepSectionCard(
                        section = StepSectionSpec(
                            title = "Alternatives",
                            icon = Icons.Default.Info,
                            accent = InfoBlue,
                            surface = InfoBlueSurface,
                            items = step.alternatives.orEmpty().map { formatAlternative(it) }
                        )
                    )
                }
            }
        }
    }
}

private fun buildStepSections(step: ProtocolStep): List<StepSectionSpec> {
    val sections = mutableListOf<StepSectionSpec>()

    if (!step.requiredActions.isNullOrEmpty()) {
        sections += StepSectionSpec(
            title = "Required actions",
            icon = Icons.Default.CheckCircle,
            accent = BrandGreenDark,
            surface = BrandGreenSurface,
            items = step.requiredActions.orEmpty()
        )
    }

    if (!step.redFlags.isNullOrEmpty()) {
        sections += StepSectionSpec(
            title = "Danger signs",
            icon = Icons.Default.Warning,
            accent = AlertRed,
            surface = AlertRedSurface,
            items = step.redFlags.orEmpty()
        )
    }

    step.criteria?.takeIf { it.isNotEmpty() }?.let { criteria ->
        sections += StepSectionSpec(
            title = "Classification",
            icon = Icons.Default.Info,
            accent = InfoBlue,
            surface = InfoBlueSurface,
            items = criteria.map { (level, description) -> "$level: $description" }
        )
    }

    if (!step.medications.isNullOrEmpty()) {
        sections += StepSectionSpec(
            title = "Medications",
            icon = Icons.Default.LocalHospital,
            accent = BrandGreenDark,
            surface = BrandGreenSurface,
            items = step.medications.orEmpty().map { formatMedication(it) }
        )
    }

    val escalationItems = buildList {
        step.escalation?.takeIf { it.isNotBlank() }?.let(::add)
        step.referralCriteria?.takeIf { it.isNotEmpty() }?.forEach { add("Refer if: $it") }
        step.referTo?.takeIf { it.isNotBlank() }?.let { add("Refer to: $it") }
    }
    if (escalationItems.isNotEmpty()) {
        sections += StepSectionSpec(
            title = "Escalation and referral",
            icon = Icons.AutoMirrored.Filled.ArrowForward,
            accent = AlertRed,
            surface = AlertRedSurface,
            items = escalationItems
        )
    }

    step.followUpDays?.let { days ->
        sections += StepSectionSpec(
            title = "Follow-up",
            icon = Icons.Default.Schedule,
            accent = InfoBlue,
            surface = InfoBlueSurface,
            items = listOf("Review again in $days day${if (days == 1) "" else "s"}")
        )
    }

    return sections
}

@Composable
private fun StepSectionCard(section: StepSectionSpec) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = section.surface,
        border = BorderStroke(1.dp, Color.White.copy(alpha = 0.5f))
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .background(section.accent.copy(alpha = 0.16f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = section.icon,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = section.accent
                    )
                }
                Text(
                    text = section.title,
                    style = MaterialTheme.typography.titleMedium,
                    color = section.accent,
                    fontWeight = FontWeight.SemiBold
                )
            }

            section.items.forEach { item ->
                Row(
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .padding(top = 7.dp)
                            .size(6.dp)
                            .background(section.accent, CircleShape)
                    )
                    Text(
                        text = item,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(
    eyebrow: String,
    title: String
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = eyebrow.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary
        )
        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
private fun EmptyProtocolState(
    searchQuery: String,
    selectedCategory: String?
) {
    val message = when {
        searchQuery.isNotBlank() -> "Try a broader diagnosis name, ICD-10 code, or medication keyword."
        selectedCategory != null -> "No protocols are currently tagged under $selectedCategory."
        else -> "No protocols are available on this device."
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = Neutral100,
        border = BorderStroke(1.dp, Neutral200)
    ) {
        Column(
            modifier = Modifier.padding(22.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Nothing to show yet",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold
            )
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ProtocolMetaPill(
    label: String,
    accent: Color,
    surface: Color,
    icon: ImageVector,
    textColor: Color = accent
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = surface
    ) {
        Row(
            modifier = Modifier
                .widthIn(max = 210.dp)
                .padding(horizontal = 10.dp, vertical = 7.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(14.dp),
                tint = textColor
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = textColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun ProtocolStatPill(
    label: String,
    background: Color = Neutral100,
    textColor: Color = MaterialTheme.colorScheme.onSurface
) {
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = background
    ) {
        Text(
            text = label,
            modifier = Modifier
                .widthIn(max = 220.dp)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            style = MaterialTheme.typography.labelMedium,
            color = textColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

private fun filterProtocols(
    protocols: List<ClinicalProtocol>,
    searchQuery: String,
    selectedCategory: String?
): List<ClinicalProtocol> {
    val categoryFiltered = selectedCategory
        ?.takeIf { it.isNotBlank() }
        ?.let { category ->
            protocols.filter { it.category.equals(category, ignoreCase = true) }
        }
        ?: protocols

    val query = searchQuery.trim().lowercase()
    val searched = if (query.isBlank()) {
        categoryFiltered
    } else {
        categoryFiltered.filter { protocol ->
            protocol.name.lowercase().contains(query) ||
                protocol.category.lowercase().contains(query) ||
                protocol.icd10Codes.any { it.lowercase().contains(query) } ||
                protocol.steps.any { step ->
                    step.title.lowercase().contains(query) ||
                        step.instructions.lowercase().contains(query) ||
                        step.requiredActions.orEmpty().any { it.lowercase().contains(query) } ||
                        step.redFlags.orEmpty().any { it.lowercase().contains(query) } ||
                        step.medications.orEmpty().any { medication ->
                            medication.name.lowercase().contains(query) ||
                                medication.dose.lowercase().contains(query) ||
                                medication.frequency.orEmpty().lowercase().contains(query)
                        }
                }
        }
    }

    return searched.sortedWith(
        compareByDescending<ClinicalProtocol> { it.urgency.equals("EMERGENCY", ignoreCase = true) }
            .thenBy { it.name }
    )
}

private fun formatApplicableTo(applicableTo: String): String = when (applicableTo) {
    "ALL" -> "All patients"
    "ADULT" -> "Adults"
    "PEDIATRIC" -> "Pediatric"
    "ADULT_FEMALE" -> "Adult women"
    else -> applicableTo.replace("_", " ").lowercase().replaceFirstChar { it.uppercase() }
}

private fun protocolPreview(protocol: ClinicalProtocol): String {
    val firstStep = protocol.steps.firstOrNull() ?: return "Stepwise clinical guidance available."
    val combined = buildString {
        append(firstStep.title.trim())
        if (firstStep.instructions.isNotBlank()) {
            append(" - ")
            append(firstStep.instructions.trim())
        }
    }
    return if (combined.length > 165) {
        combined.take(162).trimEnd() + "..."
    } else {
        combined
    }
}

private fun shortIcdSummary(icd10Codes: List<String>): String {
    if (icd10Codes.isEmpty()) return "ICD-10 pending"
    return if (icd10Codes.size <= 3) {
        "ICD-10: ${icd10Codes.joinToString(", ")}"
    } else {
        "ICD-10: ${icd10Codes.take(3).joinToString(", ")} +${icd10Codes.size - 3}"
    }
}

private fun formatMedication(medication: ProtocolMedication): String {
    val parts = buildList {
        add("${medication.name} ${medication.dose}".trim())
        medication.frequency?.takeIf { it.isNotBlank() }?.let(::add)
        medication.duration?.takeIf { it.isNotBlank() }?.let(::add)
        medication.indication?.takeIf { it.isNotBlank() }?.let { add("Note: $it") }
        medication.contraindications?.takeIf { it.isNotEmpty() }?.let {
            add("Avoid if: ${it.joinToString(", ")}")
        }
    }
    return parts.joinToString(" | ")
}

private fun formatAlternative(alternative: ProtocolAlternative): String =
    alternative.indication
        ?.takeIf { it.isNotBlank() }
        ?.let { "${alternative.name} - $it" }
        ?: alternative.name

private fun categoryVisual(category: String): ProtocolCategoryVisual = when {
    category.contains("infectious", ignoreCase = true) -> ProtocolCategoryVisual(
        icon = Icons.Default.Warning,
        accent = AlertRed,
        surface = AlertRedSurface
    )
    category.contains("maternal", ignoreCase = true) -> ProtocolCategoryVisual(
        icon = Icons.Default.FavoriteBorder,
        accent = BrandGreenDark,
        surface = BrandGreenSurface
    )
    category.contains("non-communicable", ignoreCase = true) -> ProtocolCategoryVisual(
        icon = Icons.Default.FavoriteBorder,
        accent = AccentOrange,
        surface = WarningAmberSurface
    )
    category.contains("pediatric", ignoreCase = true) -> ProtocolCategoryVisual(
        icon = Icons.Default.ChildCare,
        accent = InfoBlue,
        surface = InfoBlueSurface
    )
    category.contains("surgical", ignoreCase = true) -> ProtocolCategoryVisual(
        icon = Icons.Default.LocalHospital,
        accent = WarningAmber,
        surface = WarningAmberSurface
    )
    else -> ProtocolCategoryVisual(
        icon = Icons.Default.MedicalServices,
        accent = BrandGreenDark,
        surface = BrandGreenSurface
    )
}
