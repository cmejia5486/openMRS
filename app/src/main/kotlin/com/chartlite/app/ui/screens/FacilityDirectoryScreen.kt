package com.chartlite.app.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.chartlite.app.App
import com.chartlite.app.facilities.*
import com.chartlite.app.ui.theme.*
import androidx.compose.ui.res.stringResource
import com.chartlite.app.R

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FacilityDirectoryScreen(
    preSelectedService: String? = null,
    urgency: String? = null,
    onFacilitySelected: ((Facility) -> Unit)? = null,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val app = context.applicationContext as App
    val directory = app.facilityDirectory

    var searchQuery by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf<String?>(null) }
    var selectedService by remember { mutableStateOf(preSelectedService) }
    var selectedProvince by remember { mutableStateOf<String?>(null) }
    var selectedFacility by remember { mutableStateOf<Facility?>(null) }
    var showFilters by remember { mutableStateOf(false) }

    val allFacilities = remember { directory.getAll() }
    val types = remember { directory.getTypes() }
    val services = remember { directory.getAvailableServices() }
    val provinces = remember { directory.getProvinces() }

    val filteredFacilities = remember(searchQuery, selectedType, selectedService, selectedProvince) {
        directory.filter(
            query = searchQuery.ifBlank { null },
            type = selectedType,
            service = selectedService,
            province = selectedProvince
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        selectedFacility?.name ?: stringResource(R.string.facility_directory),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = {
                        when {
                            selectedFacility != null -> selectedFacility = null
                            else -> onBack()
                        }
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.back))
                    }
                },
                actions = {
                    if (selectedFacility == null) {
                        IconButton(onClick = { showFilters = !showFilters }) {
                            Icon(
                                if (showFilters) Icons.Default.FilterListOff else Icons.Default.FilterList,
                                stringResource(R.string.toggle_filters)
                            )
                        }
                    }
                }
            )
        }
    ) { padding ->
        selectedFacility?.let { facility ->
            FacilityDetailView(
                facility = facility,
                onSelectForReferral = if (onFacilitySelected != null) {
                    { onFacilitySelected(facility) }
                } else null,
                modifier = Modifier.padding(padding)
            )
        } ?: run {
            Column(Modifier.padding(padding)) {
                // Search bar
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                    placeholder = { Text(stringResource(R.string.search_facilities_hint)) },
                    leadingIcon = { Icon(Icons.Default.Search, null) },
                    trailingIcon = {
                        if (searchQuery.isNotBlank()) {
                            IconButton(onClick = { searchQuery = "" }) {
                                Icon(Icons.Default.Clear, stringResource(R.string.clear_all))
                            }
                        }
                    },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp)
                )

                // Filter chips
                if (showFilters) {
                    // Type filter
                    Text(stringResource(R.string.facility_type_filter), style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(start = 16.dp, top = 4.dp))
                    LazyRow(
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(types) { type ->
                            FilterChip(
                                selected = selectedType == type,
                                onClick = { selectedType = if (selectedType == type) null else type },
                                label = { Text(formatFacilityType(type), style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }

                    // Province filter
                    Text(stringResource(R.string.province_filter), style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(start = 16.dp, top = 4.dp))
                    LazyRow(
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(provinces) { province ->
                            FilterChip(
                                selected = selectedProvince == province,
                                onClick = { selectedProvince = if (selectedProvince == province) null else province },
                                label = { Text(province, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }

                    // Service filter
                    Text(stringResource(R.string.services_filter), style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(start = 16.dp, top = 4.dp))
                    LazyRow(
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(services) { service ->
                            FilterChip(
                                selected = selectedService == service,
                                onClick = { selectedService = if (selectedService == service) null else service },
                                label = { Text(service, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }

                    Spacer(Modifier.height(8.dp))
                    HorizontalDivider()
                }

                // Results count
                Text(
                    stringResource(R.string.facilities_found_format, filteredFacilities.size),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.outline,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )

                // Facility list
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(filteredFacilities, key = { it.id }) { facility ->
                        FacilityCard(
                            facility = facility,
                            onClick = { selectedFacility = facility }
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun FacilityCard(
    facility: Facility,
    onClick: () -> Unit
) {
    // Neutral card with colored left-edge accent via type badge
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Text(
                    facility.name,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.width(8.dp))
                Icon(
                    Icons.Default.ChevronRight,
                    contentDescription = null,
                    tint = Neutral400,
                    modifier = Modifier.size(20.dp)
                )
            }
            Spacer(Modifier.height(6.dp))
            // Type badge with appropriate color
            val (badgeColor, badgeTextColor) = facilityTypeBadgeColors(facility.type)
            Surface(
                color = badgeColor,
                shape = RoundedCornerShape(6.dp)
            ) {
                Text(
                    formatFacilityType(facility.type),
                    style = MaterialTheme.typography.labelSmall,
                    color = badgeTextColor,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                )
            }
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.LocationOn, null, Modifier.size(14.dp), tint = Neutral500)
                Spacer(Modifier.width(4.dp))
                Text(
                    "${facility.district}, ${facility.province}",
                    style = MaterialTheme.typography.bodySmall,
                    color = Neutral600
                )
            }
            if (facility.beds > 0) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Hotel, null, Modifier.size(14.dp), tint = Neutral500)
                    Spacer(Modifier.width(4.dp))
                    Text(
                        stringResource(R.string.beds_format, facility.beds),
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral600
                    )
                }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                facility.services.take(4).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = Neutral500,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun FacilityDetailView(
    facility: Facility,
    onSelectForReferral: (() -> Unit)?,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
                Column(Modifier.padding(16.dp)) {
                    Text(facility.name, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(6.dp))
                    val (badgeColor, badgeTextColor) = facilityTypeBadgeColors(facility.type)
                    Surface(
                        color = badgeColor,
                        shape = RoundedCornerShape(6.dp)
                    ) {
                        Text(
                            formatFacilityType(facility.type),
                            color = badgeTextColor,
                            fontWeight = FontWeight.Medium,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    DetailRow(Icons.Default.LocationOn, "${facility.subDistrict}, ${facility.district}, ${facility.province}")
                    DetailRow(Icons.Default.Phone, facility.phone)
                    DetailRow(Icons.Default.Schedule, facility.operatingHours)
                    if (facility.beds > 0) {
                        DetailRow(Icons.Default.Hotel, stringResource(R.string.beds_format, facility.beds))
                    }
                }
            }
        }

        item {
            Text(stringResource(R.string.available_services), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }

        item {
            Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
                Column(Modifier.padding(16.dp)) {
                    facility.services.forEach { service ->
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.CheckCircle, null, Modifier.size(20.dp), tint = BrandGreen)
                            Spacer(Modifier.width(8.dp))
                            Text(service, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }

        item {
            Text(stringResource(R.string.location_label), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text(
                        stringResource(R.string.coordinates_format, facility.latitude.toString(), facility.longitude.toString()),
                        style = MaterialTheme.typography.bodySmall,
                        color = Neutral600
                    )
                    Spacer(Modifier.height(8.dp))
                    // Open in Maps button
                    Button(
                        onClick = {
                            val uri = Uri.parse("geo:${facility.latitude},${facility.longitude}?q=${Uri.encode(facility.name)}")
                            val intent = Intent(Intent.ACTION_VIEW, uri)
                            context.startActivity(intent)
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Map, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.open_in_maps))
                    }
                }
            }
        }

        if (onSelectForReferral != null) {
            item {
                Button(
                    onClick = onSelectForReferral,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.AutoMirrored.Filled.Send, contentDescription = stringResource(R.string.select_for_referral))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.select_for_referral))
                }
            }
        }
    }
}

@Composable
private fun DetailRow(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, null, Modifier.size(20.dp), tint = Neutral500)
        Spacer(Modifier.width(8.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

/** Returns (backgroundColor, textColor) for facility type badges. */
@Composable
private fun facilityTypeBadgeColors(type: String): Pair<Color, Color> = when (type) {
    "TERTIARY_HOSPITAL" -> Pair(InfoBlueSurface, InfoBlue)
    "REGIONAL_HOSPITAL" -> Pair(Color(0xFFEDE7F6), Color(0xFF5E35B1))  // Light purple
    "DISTRICT_HOSPITAL" -> Pair(BrandGreenSurface, BrandGreenDark)
    "CHC" -> Pair(WarningAmberSurface, Color(0xFFE65100))
    "PHC_CLINIC" -> Pair(Neutral100, Neutral700)
    else -> Pair(Neutral100, Neutral700)
}

private fun formatFacilityType(type: String): String = when (type) {
    "TERTIARY_HOSPITAL" -> "Tertiary Hospital"
    "REGIONAL_HOSPITAL" -> "Regional Hospital"
    "DISTRICT_HOSPITAL" -> "District Hospital"
    "CHC" -> "Community Health Centre"
    "PHC_CLINIC" -> "PHC Clinic"
    else -> type.replace("_", " ").lowercase()
        .replaceFirstChar { it.uppercase() }
}
