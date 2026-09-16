const state = {
    view: "overview",
    events: [],
    alerts: [],
    rules: [],
    source: null,
    activeAlert: null,
    investigation: null,
    activeRuleId: null,
    replayResult: null,
    reports: []
};


const pageTitle =
    document.getElementById("page-title");

const workspace =
    document.getElementById("workspace-content");

const notification =
    document.getElementById("notification");

const datasetIndicator =
    document.getElementById("dataset-indicator");

const engineStatus =
    document.getElementById("engine-status");

const statusDot =
    document.getElementById("status-dot");

const fileInput =
    document.getElementById("file-input");


function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function showNotification(message, type = "info") {
    notification.textContent = message;
    notification.className = "notification";

    if (type === "error") {
        notification.classList.add("error");
    }

    notification.hidden = false;
}


function clearNotification() {
    notification.hidden = true;
    notification.textContent = "";
}


async function apiRequest(url, options = {}) {
    const response = await fetch(
        url,
        options
    );

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error(
            "AlertCraft received an invalid server response."
        );
    }

    if (!response.ok || data.success === false) {
        throw new Error(
            data.error || "Request failed."
        );
    }

    return data;
}


async function checkHealth() {
    try {
        await apiRequest("/api/health");

        engineStatus.textContent = "Online";

        statusDot.classList.remove("offline");
        statusDot.classList.add("online");

    } catch {
        engineStatus.textContent = "Offline";

        statusDot.classList.remove("online");
        statusDot.classList.add("offline");
    }
}


async function loadRules() {
    try {
        const data =
            await apiRequest("/api/rules");

        state.rules = data.rules;

    } catch (error) {
        showNotification(
            error.message,
            "error"
        );
    }
}


function updateDatasetLabel() {
    if (!state.source) {
        datasetIndicator.textContent =
            "No telemetry loaded";

        return;
    }

    if (state.source === "controlled_demo") {
        datasetIndicator.textContent =
            `${state.events.length} events · Controlled demo`;

        return;
    }

    datasetIndicator.textContent =
        `${state.events.length} events · Uploaded telemetry`;
}


function severityRank(severity) {
    const ranks = {
        Critical: 4,
        High: 3,
        Medium: 2,
        Low: 1,
        Informational: 0
    };

    return ranks[severity] ?? 0;
}


function getSeverityCounts() {
    const counts = {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0
    };

    state.alerts.forEach(alert => {
        if (
            Object.prototype.hasOwnProperty.call(
                counts,
                alert.severity
            )
        ) {
            counts[alert.severity] += 1;
        }
    });

    return counts;
}


function getUniqueValues(field) {
    return new Set(
        state.events
            .map(event => event[field])
            .filter(Boolean)
    );
}


function renderEmptyOverview() {
    workspace.innerHTML = `
        <div class="welcome-panel">

            <div class="welcome-copy">
                <p class="eyebrow">
                    ALERTCRAFT
                </p>

                <h3>
                    Detection engineering,
                    investigation and replay.
                </h3>

                <p>
                    Analyze security telemetry,
                    investigate evidence-backed alerts,
                    and test detection-rule changes
                    against the same event dataset.
                </p>
            </div>

            <div class="welcome-actions">

                <button
                    class="button button-primary"
                    id="dynamic-demo-button"
                >
                    Explore controlled demo
                </button>

                <button
                    class="button button-secondary"
                    id="dynamic-upload-button"
                >
                    Upload telemetry
                </button>

            </div>

        </div>


        <div class="empty-state">

            <div class="empty-symbol">
                AC
            </div>

            <h3>
                No telemetry loaded
            </h3>

            <p>
                Load AlertCraft's controlled SOC
                dataset or analyze your own JSON,
                LOG or TXT telemetry.
            </p>

        </div>
    `;


    document
        .getElementById("dynamic-demo-button")
        .addEventListener(
            "click",
            loadDemo
        );


    document
        .getElementById("dynamic-upload-button")
        .addEventListener(
            "click",
            () => fileInput.click()
        );
}


function renderOverview() {
    if (state.events.length === 0) {
        renderEmptyOverview();
        return;
    }


    const severity =
        getSeverityCounts();

    const hosts =
        getUniqueValues("host");

    const users =
        getUniqueValues("username");

    const sources =
        getUniqueValues("source");


    const sortedAlerts = [
        ...state.alerts
    ].sort(
        (a, b) =>
            severityRank(b.severity)
            - severityRank(a.severity)
    );


    const alertRows =
        sortedAlerts.length
            ? sortedAlerts.map(alert => `
                <button
                    class="alert-row"
                    data-alert-id="${escapeHtml(alert.alert_id)}"
                >

                    <span
                        class="severity-badge severity-${escapeHtml(
                            alert.severity.toLowerCase()
                        )}"
                    >
                        ${escapeHtml(alert.severity)}
                    </span>

                    <span class="alert-main">
                        <strong>
                            ${escapeHtml(alert.title)}
                        </strong>

                        <small>
                            ${escapeHtml(alert.rule_id)}
                            ·
                            ${escapeHtml(
                                alert.host || "Unknown host"
                            )}
                        </small>
                    </span>

                    <span class="risk-score">
                        ${escapeHtml(alert.risk_score)}
                    </span>

                </button>
            `).join("")
            : `
                <div class="table-empty">
                    No alerts were generated from
                    this telemetry.
                </div>
            `;


    workspace.innerHTML = `

        <div class="overview-heading">

            <div>
                <p class="eyebrow">
                    CURRENT ANALYSIS
                </p>

                <h3>
                    Detection overview
                </h3>

                <p>
                    Results generated from the
                    currently loaded telemetry.
                </p>
            </div>

            <div class="analysis-state">
                Analysis complete
            </div>

        </div>


        <div class="metric-grid">

            <article class="metric-card">
                <span>
                    Events analyzed
                </span>

                <strong>
                    ${state.events.length}
                </strong>

                <small>
                    Normalized telemetry
                </small>
            </article>


            <article class="metric-card">
                <span>
                    Alerts generated
                </span>

                <strong>
                    ${state.alerts.length}
                </strong>

                <small>
                    Evidence-backed detections
                </small>
            </article>


            <article class="metric-card">
                <span>
                    Critical
                </span>

                <strong>
                    ${severity.Critical}
                </strong>

                <small>
                    Highest-priority findings
                </small>
            </article>


            <article class="metric-card">
                <span>
                    High severity
                </span>

                <strong>
                    ${severity.High}
                </strong>

                <small>
                    High-priority findings
                </small>
            </article>

        </div>


        <div class="overview-grid">

            <section class="panel alert-panel">

                <div class="panel-header">

                    <div>
                        <p class="eyebrow">
                            DETECTIONS
                        </p>

                        <h4>
                            Alert queue
                        </h4>
                    </div>

                    <span class="panel-count">
                        ${state.alerts.length}
                    </span>

                </div>


                <div class="alert-list">
                    ${alertRows}
                </div>

            </section>


            <section class="panel">

                <div class="panel-header">

                    <div>
                        <p class="eyebrow">
                            TELEMETRY
                        </p>

                        <h4>
                            Dataset context
                        </h4>
                    </div>

                </div>


                <div class="context-list">

                    <div>
                        <span>
                            Hosts observed
                        </span>

                        <strong>
                            ${hosts.size}
                        </strong>
                    </div>


                    <div>
                        <span>
                            Users observed
                        </span>

                        <strong>
                            ${users.size}
                        </strong>
                    </div>


                    <div>
                        <span>
                            Log sources
                        </span>

                        <strong>
                            ${sources.size}
                        </strong>
                    </div>


                    <div>
                        <span>
                            Detection rules
                        </span>

                        <strong>
                            ${state.rules.length}
                        </strong>
                    </div>

                </div>


                <div class="source-tags">

                    ${
                        [...sources]
                            .map(source => `
                                <span>
                                    ${escapeHtml(source)}
                                </span>
                            `)
                            .join("")
                    }

                </div>

            </section>

        </div>


        <section class="panel severity-panel">

            <div class="panel-header">

                <div>
                    <p class="eyebrow">
                        PRIORITY
                    </p>

                    <h4>
                        Severity distribution
                    </h4>
                </div>

            </div>


            <div class="severity-grid">

                <div>
                    <span class="severity-marker critical"></span>

                    <strong>
                        ${severity.Critical}
                    </strong>

                    <small>
                        Critical
                    </small>
                </div>


                <div>
                    <span class="severity-marker high"></span>

                    <strong>
                        ${severity.High}
                    </strong>

                    <small>
                        High
                    </small>
                </div>


                <div>
                    <span class="severity-marker medium"></span>

                    <strong>
                        ${severity.Medium}
                    </strong>

                    <small>
                        Medium
                    </small>
                </div>


                <div>
                    <span class="severity-marker low"></span>

                    <strong>
                        ${severity.Low}
                    </strong>

                    <small>
                        Low
                    </small>
                </div>

            </div>

        </section>
    `;

    document
        .querySelectorAll(".alert-row")
        .forEach(row => {
            row.addEventListener(
                "click",
                () => openInvestigation(row.dataset.alertId)
            );
        });

}



async function openInvestigation(alertId) {
    const alert = state.alerts.find(
        item => item.alert_id === alertId
    );

    if (!alert) {
        showNotification("Alert could not be found.", "error");
        return;
    }

    showNotification("Building investigation from alert evidence...");

    try {
        const data = await apiRequest("/api/investigate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ alert })
        });

        state.view = "alerts";
        state.activeAlert = alert;
        state.investigation = data.investigation;

        activateNavigation("alerts");
        pageTitle.textContent = "Alert Investigation";

        renderInvestigation();
        clearNotification();

    } catch (error) {
        showNotification(error.message, "error");
    }
}


function getMitreItems(mitre) {
    if (!mitre) return [];
    if (Array.isArray(mitre.techniques)) return mitre.techniques;
    if (Array.isArray(mitre)) return mitre;
    return [mitre];
}


function renderInvestigation() {
    const investigation = state.investigation;

    if (!investigation) {
        renderPlaceholder(
            "Alert Investigation",
            "Select an alert from the Overview to begin an investigation."
        );
        return;
    }

    const timeline = Array.isArray(investigation.timeline)
        ? investigation.timeline
        : [];

    const entities = investigation.entities || {};
    const mitreItems = getMitreItems(investigation.mitre);

    const timelineHtml = timeline.length
        ? timeline.map(event => `
            <article class="timeline-event">
                <div class="timeline-marker"></div>

                <div class="timeline-content">
                    <div class="timeline-heading">
                        <strong>${escapeHtml(event.event_type || "Security event")}</strong>
                        <span>${escapeHtml(event.timestamp || "Timestamp unavailable")}</span>
                    </div>

                    <div class="timeline-details">
                        ${event.username ? `<span>User: <strong>${escapeHtml(event.username)}</strong></span>` : ""}
                        ${event.source_ip ? `<span>Source: <strong>${escapeHtml(event.source_ip)}</strong></span>` : ""}
                        ${event.destination_ip ? `<span>Destination: <strong>${escapeHtml(event.destination_ip)}</strong></span>` : ""}
                        ${event.host ? `<span>Host: <strong>${escapeHtml(event.host)}</strong></span>` : ""}
                        ${event.process ? `<span>Process: <strong>${escapeHtml(event.process)}</strong></span>` : ""}
                    </div>

                    ${event.command_line ? `
                        <div class="command-line">
                            ${escapeHtml(event.command_line)}
                        </div>
                    ` : ""}
                </div>
            </article>
        `).join("")
        : `<div class="table-empty">No evidence events are attached to this alert.</div>`;

    const mitreHtml = mitreItems.length
        ? mitreItems.map(item => `
            <div class="mitre-item">
                <span>
                    ${escapeHtml(item.technique || item.technique_id || item.id || "MITRE")}
                </span>

                <div>
                    <strong>
                        ${escapeHtml(item.name || item.technique_name || "Technique")}
                    </strong>
                    <small>
                        ${escapeHtml(item.tactic || item.tactic_name || "ATT&CK mapping")}
                    </small>
                </div>
            </div>
        `).join("")
        : `<p class="muted-copy">No MITRE ATT&CK mapping is attached to this detection.</p>`;

    const users = Array.isArray(entities.users) ? entities.users : [];
    const hosts = Array.isArray(entities.hosts) ? entities.hosts : [];
    const sourceIps = Array.isArray(entities.source_ips) ? entities.source_ips : [];
    const processes = Array.isArray(entities.processes) ? entities.processes : [];

    workspace.innerHTML = `
        <div class="investigation-header">
            <button class="back-button" id="back-to-overview" type="button">
                ← Overview
            </button>

            <div class="investigation-title">
                <div>
                    <span class="severity-badge severity-${escapeHtml(
                        String(investigation.severity || "Informational").toLowerCase()
                    )}">
                        ${escapeHtml(investigation.severity || "Informational")}
                    </span>

                    <span class="investigation-id">
                        ${escapeHtml(
                            investigation.alert_id ||
                            state.activeAlert?.alert_id ||
                            "Alert"
                        )}
                    </span>
                </div>

                <h3>${escapeHtml(investigation.title || "Alert Investigation")}</h3>
                <p>${escapeHtml(investigation.description || "")}</p>
            </div>

            <div class="investigation-risk">
                <span>Risk score</span>
                <strong>
                    ${escapeHtml(
                        investigation.risk_score ??
                        state.activeAlert?.risk_score ??
                        "—"
                    )}
                </strong>
            </div>
        </div>

        <div class="investigation-layout">
            <div class="investigation-main">
                <section class="panel investigation-section">
                    <div class="panel-header">
                        <div>
                            <p class="eyebrow">DETECTION LOGIC</p>
                            <h4>Why this alert fired</h4>
                        </div>
                    </div>

                    <div class="panel-body">
                        <p class="reason-copy">
                            ${escapeHtml(
                                investigation.why_fired ||
                                "Detection criteria matched the observed telemetry."
                            )}
                        </p>

                        <div class="rule-reference">
                            <span>Detection rule</span>
                            <strong>
                                ${escapeHtml(
                                    investigation.rule_id ||
                                    state.activeAlert?.rule_id ||
                                    "Unknown rule"
                                )}
                                ${investigation.rule_name
                                    ? ` · ${escapeHtml(investigation.rule_name)}`
                                    : ""}
                            </strong>
                        </div>
                    </div>
                </section>

                <section class="panel investigation-section">
                    <div class="panel-header">
                        <div>
                            <p class="eyebrow">EVIDENCE</p>
                            <h4>Event timeline</h4>
                        </div>

                        <span class="panel-count">
                            ${escapeHtml(investigation.evidence_count ?? timeline.length)}
                        </span>
                    </div>

                    <div class="timeline">
                        ${timelineHtml}
                    </div>
                </section>
            </div>

            <aside class="investigation-sidebar">
                <section class="panel investigation-section">
                    <div class="panel-header">
                        <div>
                            <p class="eyebrow">ENTITIES</p>
                            <h4>Observed context</h4>
                        </div>
                    </div>

                    <div class="entity-list">
                        <div><span>Users</span><strong>${escapeHtml(users.join(", ") || "None")}</strong></div>
                        <div><span>Hosts</span><strong>${escapeHtml(hosts.join(", ") || "None")}</strong></div>
                        <div><span>Source IPs</span><strong>${escapeHtml(sourceIps.join(", ") || "None")}</strong></div>
                        <div><span>Processes</span><strong>${escapeHtml(processes.join(", ") || "None")}</strong></div>
                    </div>
                </section>

                <section class="panel investigation-section">
                    <div class="panel-header">
                        <div>
                            <p class="eyebrow">MITRE ATT&CK</p>
                            <h4>Technique mapping</h4>
                        </div>
                    </div>

                    <div class="mitre-list">
                        ${mitreHtml}
                    </div>
                </section>

                <section class="panel investigation-section">
                    <div class="panel-header">
                        <div>
                            <p class="eyebrow">ANALYST</p>
                            <h4>Investigation decision</h4>
                        </div>
                    </div>

                    <div class="analyst-form">
                        <label>
                            Disposition
                            <select id="disposition-input">
                                <option value="">Select disposition</option>
                                <option value="True Positive">True Positive</option>
                                <option value="False Positive">False Positive</option>
                                <option value="Benign Positive">Benign Positive</option>
                                <option value="Needs Investigation">Needs Investigation</option>
                            </select>
                        </label>

                        <label>
                            Status
                            <select id="status-input">
                                <option value="New">New</option>
                                <option value="Investigating">Investigating</option>
                                <option value="Resolved">Resolved</option>
                            </select>
                        </label>

                        <label>
                            Analyst notes
                            <textarea
                                id="analyst-notes"
                                rows="5"
                                placeholder="Document investigation findings..."
                            ></textarea>
                        </label>

                        <button
                            class="button button-primary"
                            id="save-investigation"
                            type="button"
                        >
                            Save decision
                        </button>
                    </div>
                </section>
            </aside>
        </div>
    `;

    document.getElementById("disposition-input").value =
        investigation.disposition || "";

    document.getElementById("status-input").value =
        investigation.status || "New";

    document.getElementById("analyst-notes").value =
        investigation.notes || "";

    document
        .getElementById("back-to-overview")
        .addEventListener(
            "click",
            () => selectView("overview")
        );

    document
        .getElementById("save-investigation")
        .addEventListener(
            "click",
            saveInvestigationDecision
        );
}


async function saveInvestigationDecision() {
    if (!state.activeAlert) {
        showNotification(
            "No active alert is available to update.",
            "error"
        );
        return;
    }

    const disposition =
        document.getElementById("disposition-input").value;

    const status =
        document.getElementById("status-input").value;

    const notes =
        document.getElementById("analyst-notes").value;

    if (!disposition) {
        showNotification(
            "Select an analyst disposition before saving.",
            "error"
        );
        return;
    }

    try {
        const data = await apiRequest("/api/investigate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                alert: state.activeAlert,
                disposition,
                status,
                notes
            })
        });

        state.investigation = data.investigation;
        renderInvestigation();

        showNotification(
            `Investigation saved as ${disposition}.`
        );

    } catch (error) {
        showNotification(error.message, "error");
    }
}

function getTelemetryFilterOptions(field) {
    return [
        ...new Set(
            state.events
                .map(event => event[field])
                .filter(Boolean)
        )
    ].sort();
}


function getFilteredTelemetry() {
    const search =
        document
            .getElementById("telemetry-search")
            ?.value
            .trim()
            .toLowerCase() || "";

    const source =
        document
            .getElementById("telemetry-source-filter")
            ?.value || "";

    const eventType =
        document
            .getElementById("telemetry-type-filter")
            ?.value || "";


    return state.events.filter(event => {
        const matchesSource =
            !source ||
            event.source === source;

        const matchesType =
            !eventType ||
            event.event_type === eventType;

        const searchableValues = [
            event.timestamp,
            event.host,
            event.source,
            event.event_id,
            event.event_type,
            event.username,
            event.source_ip,
            event.destination_ip,
            event.status,
            event.process,
            event.parent_process,
            event.command_line
        ]
            .filter(value => value !== null && value !== undefined)
            .join(" ")
            .toLowerCase();

        const matchesSearch =
            !search ||
            searchableValues.includes(search);

        return (
            matchesSource &&
            matchesType &&
            matchesSearch
        );
    });
}


function renderTelemetry() {
    if (state.events.length === 0) {
        workspace.innerHTML = `
            <div class="section-placeholder">
                <p class="eyebrow">
                    TELEMETRY
                </p>

                <h3>
                    No telemetry loaded
                </h3>

                <p>
                    Load the controlled demo or upload
                    telemetry before opening the explorer.
                </p>

                <button
                    class="button button-primary"
                    id="telemetry-load-demo"
                    type="button"
                >
                    Load controlled demo
                </button>
            </div>
        `;

        document
            .getElementById("telemetry-load-demo")
            .addEventListener(
                "click",
                loadDemo
            );

        return;
    }


    const sources =
        getTelemetryFilterOptions("source");

    const eventTypes =
        getTelemetryFilterOptions("event_type");


    workspace.innerHTML = `
        <div class="telemetry-heading">

            <div>
                <p class="eyebrow">
                    EVENT DATA
                </p>

                <h3>
                    Telemetry Explorer
                </h3>

                <p>
                    Inspect normalized security events
                    and their underlying evidence.
                </p>
            </div>

            <div class="telemetry-total">
                <strong>
                    ${state.events.length}
                </strong>

                <span>
                    events
                </span>
            </div>

        </div>


        <section class="panel telemetry-panel">

            <div class="telemetry-toolbar">

                <div class="telemetry-search-wrap">

                    <input
                        id="telemetry-search"
                        class="telemetry-search"
                        type="search"
                        placeholder="Search user, host, IP, process..."
                        autocomplete="off"
                    >

                </div>


                <select
                    id="telemetry-source-filter"
                    class="telemetry-filter"
                >
                    <option value="">
                        All sources
                    </option>

                    ${
                        sources
                            .map(source => `
                                <option
                                    value="${escapeHtml(source)}"
                                >
                                    ${escapeHtml(source)}
                                </option>
                            `)
                            .join("")
                    }

                </select>


                <select
                    id="telemetry-type-filter"
                    class="telemetry-filter"
                >
                    <option value="">
                        All event types
                    </option>

                    ${
                        eventTypes
                            .map(type => `
                                <option
                                    value="${escapeHtml(type)}"
                                >
                                    ${escapeHtml(type)}
                                </option>
                            `)
                            .join("")
                    }

                </select>

            </div>


            <div class="telemetry-result-bar">

                <span id="telemetry-result-count">
                    ${state.events.length}
                    events shown
                </span>

            </div>


            <div class="telemetry-table-wrap">

                <table class="telemetry-table">

                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Event</th>
                            <th>User</th>
                            <th>Host</th>
                            <th>Source IP</th>
                            <th>Status</th>
                        </tr>
                    </thead>

                    <tbody id="telemetry-table-body">
                    </tbody>

                </table>

            </div>

        </section>


        <div
            class="event-drawer"
            id="event-drawer"
            hidden
        >

            <div
                class="event-drawer-backdrop"
                id="event-drawer-backdrop"
            ></div>


            <aside class="event-drawer-panel">

                <div class="event-drawer-header">

                    <div>
                        <p class="eyebrow">
                            EVENT EVIDENCE
                        </p>

                        <h3 id="event-drawer-title">
                            Security event
                        </h3>
                    </div>

                    <button
                        class="event-drawer-close"
                        id="event-drawer-close"
                        type="button"
                        aria-label="Close event details"
                    >
                        ×
                    </button>

                </div>


                <div
                    class="event-drawer-content"
                    id="event-drawer-content"
                ></div>

            </aside>

        </div>
    `;


    const searchInput =
        document.getElementById(
            "telemetry-search"
        );

    const sourceFilter =
        document.getElementById(
            "telemetry-source-filter"
        );

    const typeFilter =
        document.getElementById(
            "telemetry-type-filter"
        );


    const refresh =
        () => renderTelemetryRows(
            getFilteredTelemetry()
        );


    searchInput.addEventListener(
        "input",
        refresh
    );

    sourceFilter.addEventListener(
        "change",
        refresh
    );

    typeFilter.addEventListener(
        "change",
        refresh
    );


    document
        .getElementById("event-drawer-close")
        .addEventListener(
            "click",
            closeEventDrawer
        );


    document
        .getElementById(
            "event-drawer-backdrop"
        )
        .addEventListener(
            "click",
            closeEventDrawer
        );


    renderTelemetryRows(
        state.events
    );
}


function renderTelemetryRows(events) {
    const body =
        document.getElementById(
            "telemetry-table-body"
        );

    const count =
        document.getElementById(
            "telemetry-result-count"
        );


    if (!body || !count) {
        return;
    }


    count.textContent =
        `${events.length} ${
            events.length === 1
                ? "event"
                : "events"
        } shown`;


    if (events.length === 0) {
        body.innerHTML = `
            <tr>
                <td
                    colspan="7"
                    class="telemetry-empty"
                >
                    No telemetry matches
                    the current filters.
                </td>
            </tr>
        `;

        return;
    }


    body.innerHTML =
        events
            .map(event => `

                <tr
                    class="telemetry-row"
                    data-event-uid="${escapeHtml(
                        event.event_uid
                    )}"
                >

                    <td class="mono-cell">
                        ${escapeHtml(
                            event.timestamp ||
                            "—"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.source ||
                            "Unknown"
                        )}
                    </td>

                    <td>
                        <div class="event-type-cell">

                            <strong>
                                ${escapeHtml(
                                    event.event_type ||
                                    "event"
                                )}
                            </strong>

                            <small>
                                ${escapeHtml(
                                    event.event_id ||
                                    "No event ID"
                                )}
                            </small>

                        </div>
                    </td>

                    <td>
                        ${escapeHtml(
                            event.username ||
                            "—"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.host ||
                            "—"
                        )}
                    </td>

                    <td class="mono-cell">
                        ${escapeHtml(
                            event.source_ip ||
                            "—"
                        )}
                    </td>

                    <td>
                        ${
                            event.status
                                ? `
                                    <span
                                        class="event-status event-status-${escapeHtml(
                                            String(
                                                event.status
                                            )
                                                .toLowerCase()
                                                .replaceAll(
                                                    " ",
                                                    "-"
                                                )
                                        )}"
                                    >
                                        ${escapeHtml(
                                            event.status
                                        )}
                                    </span>
                                `
                                : "—"
                        }
                    </td>

                </tr>

            `)
            .join("");


    document
        .querySelectorAll(
            ".telemetry-row"
        )
        .forEach(row => {

            row.addEventListener(
                "click",
                () => {
                    openEventDrawer(
                        row.dataset.eventUid
                    );
                }
            );

        });
}


function addEventField(
    container,
    label,
    value
) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return;
    }


    const item =
        document.createElement("div");

    item.className =
        "event-field";


    const labelElement =
        document.createElement("span");

    labelElement.textContent =
        label;


    const valueElement =
        document.createElement("strong");

    valueElement.textContent =
        String(value);


    item.appendChild(
        labelElement
    );

    item.appendChild(
        valueElement
    );

    container.appendChild(
        item
    );
}


function openEventDrawer(eventUid) {
    const event =
        state.events.find(
            item =>
                item.event_uid ===
                eventUid
        );


    if (!event) {
        showNotification(
            "Telemetry event could not be found.",
            "error"
        );

        return;
    }


    const drawer =
        document.getElementById(
            "event-drawer"
        );

    const title =
        document.getElementById(
            "event-drawer-title"
        );

    const content =
        document.getElementById(
            "event-drawer-content"
        );


    title.textContent =
        event.event_type ||
        "Security event";


    content.replaceChildren();


    const fields =
        document.createElement("div");

    fields.className =
        "event-field-grid";


    addEventField(
        fields,
        "Timestamp",
        event.timestamp
    );

    addEventField(
        fields,
        "Event ID",
        event.event_id
    );

    addEventField(
        fields,
        "Source",
        event.source
    );

    addEventField(
        fields,
        "Host",
        event.host
    );

    addEventField(
        fields,
        "Username",
        event.username
    );

    addEventField(
        fields,
        "Source IP",
        event.source_ip
    );

    addEventField(
        fields,
        "Destination IP",
        event.destination_ip
    );

    addEventField(
        fields,
        "Status",
        event.status
    );

    addEventField(
        fields,
        "Logon type",
        event.logon_type
    );

    addEventField(
        fields,
        "Process",
        event.process
    );

    addEventField(
        fields,
        "Parent process",
        event.parent_process
    );

    addEventField(
        fields,
        "Command line",
        event.command_line
    );


    content.appendChild(
        fields
    );


    const rawSection =
        document.createElement("section");

    rawSection.className =
        "raw-event-section";


    const rawHeading =
        document.createElement("div");

    rawHeading.className =
        "raw-event-heading";


    const eyebrow =
        document.createElement("p");

    eyebrow.className =
        "eyebrow";

    eyebrow.textContent =
        "RAW EVIDENCE";


    const heading =
        document.createElement("h4");

    heading.textContent =
        "Original event";


    rawHeading.appendChild(
        eyebrow
    );

    rawHeading.appendChild(
        heading
    );


    const raw =
        document.createElement("pre");

    raw.className =
        "raw-event";


    /*
        textContent is deliberate here.
        Uploaded telemetry must never
        be inserted into the page as HTML.
    */

    raw.textContent =
        typeof event.raw_event ===
        "string"
            ? event.raw_event
            : JSON.stringify(
                event.raw_event,
                null,
                2
            );


    rawSection.appendChild(
        rawHeading
    );

    rawSection.appendChild(
        raw
    );


    content.appendChild(
        rawSection
    );


    drawer.hidden = false;

    document.body.classList.add(
        "drawer-open"
    );
}


function closeEventDrawer() {
    const drawer =
        document.getElementById(
            "event-drawer"
        );

    if (drawer) {
        drawer.hidden = true;
    }

    document.body.classList.remove(
        "drawer-open"
    );
}


function getRuleMitreItems(rule) {
    if (!rule?.mitre) {
        return [];
    }

    if (Array.isArray(rule.mitre.techniques)) {
        return rule.mitre.techniques;
    }

    if (Array.isArray(rule.mitre)) {
        return rule.mitre;
    }

    return [rule.mitre];
}


function getRuleParameterSummary(rule) {
    const parameters = [];

    if (rule.threshold !== null && rule.threshold !== undefined) {
        parameters.push({
            label: "Threshold",
            value: String(rule.threshold)
        });
    }

    if (
        rule.window_minutes !== null &&
        rule.window_minutes !== undefined
    ) {
        parameters.push({
            label: "Window",
            value: `${rule.window_minutes} min`
        });
    }

    parameters.push({
        label: "Enabled",
        value: rule.enabled === false ? "No" : "Yes"
    });

    return parameters;
}


function renderRules() {
    if (!state.rules.length) {
        workspace.innerHTML = `
            <div class="section-placeholder">
                <p class="eyebrow">DETECTION ENGINEERING</p>
                <h3>No detection rules available</h3>
                <p>
                    AlertCraft could not load the configured detection rules.
                </p>
            </div>
        `;
        return;
    }

    if (
        !state.activeRuleId ||
        !state.rules.some(rule => rule.id === state.activeRuleId)
    ) {
        state.activeRuleId = state.rules[0].id;
    }

    const activeRule = state.rules.find(
        rule => rule.id === state.activeRuleId
    );

    const ruleCards = state.rules.map(rule => {
        const isActive = rule.id === state.activeRuleId;
        const enabled = rule.enabled !== false;

        return `
            <button
                class="rule-card ${isActive ? "active" : ""}"
                data-rule-id="${escapeHtml(rule.id)}"
                type="button"
            >
                <div class="rule-card-top">
                    <span class="rule-id">
                        ${escapeHtml(rule.id)}
                    </span>

                    <span class="rule-state ${enabled ? "enabled" : "disabled"}">
                        ${enabled ? "Enabled" : "Disabled"}
                    </span>
                </div>

                <strong class="rule-card-title">
                    ${escapeHtml(rule.name || "Detection rule")}
                </strong>

                <div class="rule-card-meta">
                    <span
                        class="severity-badge severity-${escapeHtml(
                            String(rule.severity || "Informational").toLowerCase()
                        )}"
                    >
                        ${escapeHtml(rule.severity || "Informational")}
                    </span>

                    <span>
                        ${escapeHtml(rule.type || "rule")}
                    </span>
                </div>
            </button>
        `;
    }).join("");

    const parameters = getRuleParameterSummary(activeRule);

    const parameterHtml = parameters.map(parameter => `
        <div class="rule-parameter">
            <span>${escapeHtml(parameter.label)}</span>
            <strong>${escapeHtml(parameter.value)}</strong>
        </div>
    `).join("");

    const mitreItems = getRuleMitreItems(activeRule);

    const mitreHtml = mitreItems.length
        ? mitreItems.map(item => `
            <div class="mitre-item">
                <span>
                    ${escapeHtml(
                        item.technique ||
                        item.technique_id ||
                        item.id ||
                        "MITRE"
                    )}
                </span>

                <div>
                    <strong>
                        ${escapeHtml(
                            item.name ||
                            item.technique_name ||
                            "Technique"
                        )}
                    </strong>

                    <small>
                        ${escapeHtml(
                            item.tactic ||
                            item.tactic_name ||
                            "ATT&CK mapping"
                        )}
                    </small>
                </div>
            </div>
        `).join("")
        : `
            <p class="muted-copy">
                No MITRE ATT&CK mapping is configured for this rule.
            </p>
        `;

    const matchingAlerts = state.alerts.filter(
        alert => alert.rule_id === activeRule.id
    );

    workspace.innerHTML = `
        <div class="rules-heading">
            <div>
                <p class="eyebrow">DETECTION ENGINEERING</p>

                <h3>Detection Rules</h3>

                <p>
                    Inspect the rules currently loaded by AlertCraft's
                    detection engine.
                </p>
            </div>

            <div class="rules-total">
                <strong>${state.rules.length}</strong>
                <span>rules</span>
            </div>
        </div>

        <div class="rules-layout">
            <section class="rules-list">
                ${ruleCards}
            </section>

            <section class="panel rule-detail">
                <div class="rule-detail-header">
                    <div>
                        <div class="rule-detail-badges">
                            <span class="rule-id">
                                ${escapeHtml(activeRule.id)}
                            </span>

                            <span
                                class="severity-badge severity-${escapeHtml(
                                    String(
                                        activeRule.severity || "Informational"
                                    ).toLowerCase()
                                )}"
                            >
                                ${escapeHtml(
                                    activeRule.severity || "Informational"
                                )}
                            </span>
                        </div>

                        <h3>
                            ${escapeHtml(activeRule.name || "Detection rule")}
                        </h3>

                        <p>
                            ${escapeHtml(
                                activeRule.description ||
                                "No rule description is configured."
                            )}
                        </p>
                    </div>

                    <span class="rule-state ${
                        activeRule.enabled === false
                            ? "disabled"
                            : "enabled"
                    }">
                        ${
                            activeRule.enabled === false
                                ? "Disabled"
                                : "Enabled"
                        }
                    </span>
                </div>

                <div class="rule-detail-grid">
                    <section class="rule-detail-section">
                        <p class="eyebrow">DETECTION LOGIC</p>
                        <h4>Rule configuration</h4>

                        <div class="rule-type-block">
                            <span>Detector type</span>
                            <strong>
                                ${escapeHtml(activeRule.type || "Unknown")}
                            </strong>
                        </div>

                        <div class="rule-parameter-grid">
                            ${parameterHtml}
                        </div>
                    </section>

                    <section class="rule-detail-section">
                        <p class="eyebrow">MITRE ATT&CK</p>
                        <h4>Technique mapping</h4>

                        <div class="mitre-list rule-mitre-list">
                            ${mitreHtml}
                        </div>
                    </section>
                </div>

                <section class="rule-detail-section rule-analysis-section">
                    <div class="rule-section-heading">
                        <div>
                            <p class="eyebrow">CURRENT DATASET</p>
                            <h4>Detection activity</h4>
                        </div>

                        <span class="panel-count">
                            ${matchingAlerts.length}
                        </span>
                    </div>

                    ${
                        state.events.length
                            ? `
                                <p class="rule-analysis-copy">
                                    This rule generated
                                    <strong>${matchingAlerts.length}</strong>
                                    ${
                                        matchingAlerts.length === 1
                                            ? "alert"
                                            : "alerts"
                                    }
                                    from the currently loaded
                                    ${state.events.length}-event dataset.
                                </p>
                            `
                            : `
                                <p class="rule-analysis-copy">
                                    Load telemetry to see whether this rule
                                    produces alerts against the current dataset.
                                </p>
                            `
                    }
                </section>

                <section class="rule-tuning-note">
                    <div>
                        <p class="eyebrow">TUNING WORKFLOW</p>
                        <strong>Changes are tested through Replay.</strong>
                    </div>

                    <p>
                        AlertCraft keeps the configured rule unchanged while
                        temporary threshold, time-window or enabled-state
                        changes are tested against the same telemetry.
                    </p>
                </section>
            </section>
        </div>
    `;

    document
        .querySelectorAll(".rule-card")
        .forEach(card => {
            card.addEventListener(
                "click",
                () => {
                    state.activeRuleId = card.dataset.ruleId;
                    renderRules();
                }
            );
        });
}


function getReplayRule() {
    const replayableRules = state.rules.filter(rule => rule?.id);

    if (!replayableRules.length) {
        return null;
    }

    const selected = replayableRules.find(
        rule => rule.id === state.activeRuleId
    );

    return selected || replayableRules[0];
}


function renderReplay() {
    if (!state.events.length) {
        workspace.innerHTML = `
            <div class="section-placeholder">
                <p class="eyebrow">DETECTION REPLAY</p>
                <h3>No telemetry loaded</h3>
                <p>
                    Replay needs a telemetry dataset so the same events can be
                    evaluated before and after a temporary rule change.
                </p>

                <button
                    class="button button-primary"
                    id="replay-load-demo"
                    type="button"
                >
                    Load controlled demo
                </button>
            </div>
        `;

        document
            .getElementById("replay-load-demo")
            .addEventListener("click", loadDemo);

        return;
    }

    const activeRule = getReplayRule();

    if (!activeRule) {
        renderPlaceholder(
            "Detection Replay",
            "No detection rules are available for replay."
        );
        return;
    }

    state.activeRuleId = activeRule.id;

    const ruleOptions = state.rules.map(rule => `
        <option
            value="${escapeHtml(rule.id)}"
            ${rule.id === activeRule.id ? "selected" : ""}
        >
            ${escapeHtml(rule.id)} · ${escapeHtml(rule.name || "Detection rule")}
        </option>
    `).join("");

    const thresholdField =
        activeRule.threshold !== null &&
        activeRule.threshold !== undefined
            ? `
                <label class="replay-field">
                    <span>Threshold</span>
                    <input
                        id="replay-threshold"
                        type="number"
                        min="1"
                        max="1000"
                        step="1"
                        value="${escapeHtml(activeRule.threshold)}"
                    >
                    <small>Temporary match threshold</small>
                </label>
            `
            : "";

    const windowField =
        activeRule.window_minutes !== null &&
        activeRule.window_minutes !== undefined
            ? `
                <label class="replay-field">
                    <span>Window</span>

                    <div class="replay-input-suffix">
                        <input
                            id="replay-window"
                            type="number"
                            min="1"
                            max="1440"
                            step="1"
                            value="${escapeHtml(activeRule.window_minutes)}"
                        >
                        <em>min</em>
                    </div>

                    <small>Temporary correlation window</small>
                </label>
            `
            : "";

    const resultHtml = renderReplayResultMarkup(
        state.replayResult,
        activeRule.id
    );

    workspace.innerHTML = `
        <div class="replay-heading">
            <div>
                <p class="eyebrow">DETECTION ENGINEERING</p>
                <h3>Detection Replay</h3>
                <p>
                    Test temporary rule changes against the exact same
                    normalized telemetry.
                </p>
            </div>

            <div class="replay-dataset">
                <strong>${state.events.length}</strong>
                <span>events fixed for replay</span>
            </div>
        </div>

        <div class="replay-layout">
            <section class="panel replay-config">
                <div class="panel-header">
                    <div>
                        <p class="eyebrow">EXPERIMENT</p>
                        <h4>Rule tuning</h4>
                    </div>
                </div>

                <div class="replay-form">
                    <label class="replay-field replay-rule-field">
                        <span>Detection rule</span>
                        <select id="replay-rule-select">
                            ${ruleOptions}
                        </select>
                        <small>
                            Choose the configured rule to test.
                        </small>
                    </label>

                    <div class="replay-baseline">
                        <div>
                            <span>Configured severity</span>
                            <strong>
                                ${escapeHtml(
                                    activeRule.severity || "Informational"
                                )}
                            </strong>
                        </div>

                        <div>
                            <span>Detector type</span>
                            <strong>
                                ${escapeHtml(activeRule.type || "Unknown")}
                            </strong>
                        </div>
                    </div>

                    <div class="replay-fields-grid">
                        ${thresholdField}
                        ${windowField}

                        <label class="replay-field replay-toggle-field">
                            <span>Enabled</span>

                            <div class="replay-toggle-row">
                                <input
                                    id="replay-enabled"
                                    type="checkbox"
                                    ${activeRule.enabled === false ? "" : "checked"}
                                >
                                <strong id="replay-enabled-label">
                                    ${
                                        activeRule.enabled === false
                                            ? "Disabled"
                                            : "Enabled"
                                    }
                                </strong>
                            </div>

                            <small>Temporary enabled state</small>
                        </label>
                    </div>

                    <div class="replay-safety-note">
                        <strong>Non-destructive test</strong>
                        <p>
                            Replay sends a temporary copy of these settings to
                            the backend. The configured rule in rules.json is
                            not modified.
                        </p>
                    </div>

                    <button
                        class="button button-primary replay-run-button"
                        id="run-replay"
                        type="button"
                    >
                        Run replay
                    </button>
                </div>
            </section>

            <section class="panel replay-results" id="replay-results">
                ${resultHtml}
            </section>
        </div>
    `;

    document
        .getElementById("replay-rule-select")
        .addEventListener("change", event => {
            state.activeRuleId = event.target.value;
            state.replayResult = null;
            renderReplay();
        });

    const enabledInput =
        document.getElementById("replay-enabled");

    enabledInput.addEventListener("change", () => {
        document.getElementById("replay-enabled-label").textContent =
            enabledInput.checked ? "Enabled" : "Disabled";
    });

    document
        .getElementById("run-replay")
        .addEventListener("click", runReplay);
}


function renderReplayResultMarkup(result, activeRuleId) {
    if (!result || result.rule_id !== activeRuleId) {
        return `
            <div class="replay-empty">
                <div class="replay-empty-symbol">↻</div>

                <p class="eyebrow">BEFORE / AFTER</p>
                <h3>Run a tuning experiment</h3>

                <p>
                    Change a supported rule parameter and replay this dataset.
                    AlertCraft will compare the baseline detection result with
                    the temporary tuned result.
                </p>
            </div>
        `;
    }

    const replay = result.data;
    const beforeCount = replay.before?.alert_count ?? 0;
    const afterCount = replay.after?.alert_count ?? 0;
    const difference =
        replay.comparison?.difference ??
        (afterCount - beforeCount);

    const effect =
        replay.comparison?.effect || "no_count_change";

    const effectLabels = {
        fewer_alerts: "Fewer alerts",
        more_alerts: "More alerts",
        no_count_change: "No count change"
    };

    const effectLabel =
        effectLabels[effect] || "Replay complete";

    const differenceLabel =
        difference > 0
            ? `+${difference}`
            : String(difference);

    const changes = replay.changes || {};

    const changeRows = Object.entries(changes).length
        ? Object.entries(changes).map(([key, value]) => `
            <div class="replay-change-row">
                <span>
                    ${escapeHtml(
                        key
                            .replaceAll("_", " ")
                            .replace(/\b\w/g, letter => letter.toUpperCase())
                    )}
                </span>
                <strong>${escapeHtml(value)}</strong>
            </div>
        `).join("")
        : `
            <p class="muted-copy">
                No parameter differences were reported.
            </p>
        `;

    return `
        <div class="replay-result-header">
            <div>
                <p class="eyebrow">REPLAY COMPLETE</p>
                <h3>${escapeHtml(activeRuleId)}</h3>
            </div>

            <span class="replay-effect replay-effect-${escapeHtml(effect)}">
                ${escapeHtml(effectLabel)}
            </span>
        </div>

        <div class="replay-comparison">
            <article>
                <span>Baseline</span>
                <strong>${beforeCount}</strong>
                <small>
                    ${
                        beforeCount === 1
                            ? "alert"
                            : "alerts"
                    }
                </small>
            </article>

            <div class="replay-arrow">→</div>

            <article>
                <span>Tuned</span>
                <strong>${afterCount}</strong>
                <small>
                    ${
                        afterCount === 1
                            ? "alert"
                            : "alerts"
                    }
                </small>
            </article>
        </div>

        <div class="replay-difference">
            <span>Alert-count difference</span>
            <strong>${escapeHtml(differenceLabel)}</strong>
        </div>

        <section class="replay-result-section">
            <p class="eyebrow">TEMPORARY CHANGES</p>
            <h4>Parameters tested</h4>
            <div class="replay-change-list">
                ${changeRows}
            </div>
        </section>

        <section class="replay-result-section">
            <p class="eyebrow">INTERPRETATION</p>
            <h4>What changed?</h4>

            <p class="replay-interpretation">
                ${
                    effect === "fewer_alerts"
                        ? "The tuned rule generated fewer alerts against the same telemetry. Review the lost detections before treating this as an improvement."
                        : effect === "more_alerts"
                            ? "The tuned rule generated more alerts against the same telemetry. Inspect the additional detections to determine whether sensitivity improved or noise increased."
                            : "The alert count did not change. The tuning may still have changed which evidence matched, so count alone should not be treated as proof of equivalent behavior."
                }
            </p>
        </section>

        <div class="replay-integrity">
            <span>Dataset held constant</span>
            <strong>
                ${escapeHtml(replay.telemetry_event_count ?? state.events.length)}
                events
            </strong>
        </div>
    `;
}


async function runReplay() {
    const activeRule = getReplayRule();

    if (!activeRule) {
        showNotification(
            "No detection rule is available for replay.",
            "error"
        );
        return;
    }

    const changes = {};

    const thresholdInput =
        document.getElementById("replay-threshold");

    const windowInput =
        document.getElementById("replay-window");

    const enabledInput =
        document.getElementById("replay-enabled");

    if (thresholdInput) {
        const threshold = Number(thresholdInput.value);

        if (!Number.isInteger(threshold) || threshold < 1 || threshold > 1000) {
            showNotification(
                "Threshold must be a whole number from 1 to 1000.",
                "error"
            );
            return;
        }

        changes.threshold = threshold;
    }

    if (windowInput) {
        const windowMinutes = Number(windowInput.value);

        if (
            !Number.isInteger(windowMinutes) ||
            windowMinutes < 1 ||
            windowMinutes > 1440
        ) {
            showNotification(
                "Window must be a whole number from 1 to 1440 minutes.",
                "error"
            );
            return;
        }

        changes.window_minutes = windowMinutes;
    }

    changes.enabled = enabledInput.checked;

    showNotification(
        `Replaying ${activeRule.id} against ${state.events.length} events...`
    );

    const runButton =
        document.getElementById("run-replay");

    runButton.disabled = true;
    runButton.textContent = "Running replay...";

    try {
        const data = await apiRequest("/api/replay", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                events: state.events,
                rule_id: activeRule.id,
                changes
            })
        });

        state.replayResult = {
            rule_id: activeRule.id,
            data: data.replay
        };

        renderReplay();

        const replay = data.replay;

        showNotification(
            `Replay complete: ${replay.before.alert_count} → ${replay.after.alert_count} alerts.`
        );

    } catch (error) {
        showNotification(error.message, "error");

        runButton.disabled = false;
        runButton.textContent = "Run replay";
    }
}


function getReportSourceLabel() {
    if (state.source === "controlled_demo") {
        return "AlertCraft Controlled SOC Lab";
    }

    if (state.source === "uploaded_telemetry") {
        return "Uploaded telemetry";
    }

    return "Current telemetry";
}


function getReportMitreMappings() {
    const seen = new Set();
    const mappings = [];

    state.alerts.forEach(alert => {
        getMitreItems(alert.mitre).forEach(item => {
            const technique =
                item.technique ||
                item.technique_id ||
                item.id ||
                "MITRE";

            const name =
                item.name ||
                item.technique_name ||
                "Technique";

            const tactic =
                item.tactic ||
                item.tactic_name ||
                "ATT&CK mapping";

            const key = `${technique}|${name}|${tactic}`;

            if (!seen.has(key)) {
                seen.add(key);
                mappings.push({
                    technique,
                    name,
                    tactic
                });
            }
        });
    });

    return mappings;
}


function buildReportSnapshot() {
    const severity = getSeverityCounts();

    const alerts = [...state.alerts]
        .sort(
            (a, b) =>
                severityRank(b.severity) -
                severityRank(a.severity)
        )
        .map(alert => ({
            alert_id: alert.alert_id,
            rule_id: alert.rule_id,
            title: alert.title,
            description: alert.description || "",
            severity: alert.severity,
            risk_score: alert.risk_score,
            host: alert.host || "",
            username: alert.username || "",
            source_ip: alert.source_ip || "",
            evidence_count:
                Array.isArray(alert.evidence)
                    ? alert.evidence.length
                    : 0,
            mitre: getMitreItems(alert.mitre)
        }));

    const investigation =
        state.investigation && state.activeAlert
            ? {
                alert_id:
                    state.investigation.alert_id ||
                    state.activeAlert.alert_id,
                title:
                    state.investigation.title ||
                    state.activeAlert.title,
                severity:
                    state.investigation.severity ||
                    state.activeAlert.severity,
                disposition:
                    state.investigation.disposition || "",
                status:
                    state.investigation.status || "New",
                notes:
                    state.investigation.notes || "",
                evidence_count:
                    state.investigation.evidence_count ??
                    (
                        Array.isArray(state.investigation.timeline)
                            ? state.investigation.timeline.length
                            : 0
                    )
            }
            : null;

    const replay =
        state.replayResult
            ? {
                rule_id: state.replayResult.rule_id,
                before:
                    state.replayResult.data?.before?.alert_count ?? 0,
                after:
                    state.replayResult.data?.after?.alert_count ?? 0,
                effect:
                    state.replayResult.data?.comparison?.effect ||
                    "no_count_change",
                difference:
                    state.replayResult.data?.comparison?.difference ??
                    (
                        (
                            state.replayResult.data?.after?.alert_count ??
                            0
                        ) -
                        (
                            state.replayResult.data?.before?.alert_count ??
                            0
                        )
                    ),
                changes:
                    state.replayResult.data?.changes || {},
                telemetry_event_count:
                    state.replayResult.data?.telemetry_event_count ??
                    state.events.length
            }
            : null;

    return {
        report_id:
            `ACR-${Date.now().toString(36).toUpperCase()}`,
        generated_at:
            new Date().toISOString(),
        source:
            getReportSourceLabel(),
        event_count:
            state.events.length,
        alert_count:
            state.alerts.length,
        severity,
        hosts:
            [...getUniqueValues("host")],
        users:
            [...getUniqueValues("username")],
        sources:
            [...getUniqueValues("source")],
        rules_loaded:
            state.rules.length,
        alerts,
        mitre:
            getReportMitreMappings(),
        investigation,
        replay
    };
}


function formatReportTimestamp(value) {
    if (!value) {
        return "Unavailable";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}


function renderReportAlertRows(report) {
    if (!report.alerts.length) {
        return `
            <tr>
                <td colspan="6" class="report-table-empty">
                    No alerts were generated from this telemetry.
                </td>
            </tr>
        `;
    }

    return report.alerts.map(alert => `
        <tr>
            <td>
                <span
                    class="severity-badge severity-${escapeHtml(
                        String(
                            alert.severity || "Informational"
                        ).toLowerCase()
                    )}"
                >
                    ${escapeHtml(alert.severity || "Informational")}
                </span>
            </td>

            <td>
                <strong>${escapeHtml(alert.title || "Detection")}</strong>
                <small>${escapeHtml(alert.rule_id || "Unknown rule")}</small>
            </td>

            <td>${escapeHtml(alert.host || "—")}</td>
            <td>${escapeHtml(alert.username || "—")}</td>
            <td>${escapeHtml(alert.risk_score ?? "—")}</td>
            <td>${escapeHtml(alert.evidence_count)}</td>
        </tr>
    `).join("");
}


function renderReportMitre(report) {
    if (!report.mitre.length) {
        return `
            <p class="muted-copy">
                No MITRE ATT&CK mappings were attached to the current findings.
            </p>
        `;
    }

    return report.mitre.map(item => `
        <div class="report-mitre-item">
            <span>${escapeHtml(item.technique)}</span>

            <div>
                <strong>${escapeHtml(item.name)}</strong>
                <small>${escapeHtml(item.tactic)}</small>
            </div>
        </div>
    `).join("");
}


function renderReportInvestigation(report) {
    if (!report.investigation) {
        return `
            <div class="report-optional-empty">
                No alert investigation is attached to this report snapshot.
                Open an alert and investigate it to include analyst context.
            </div>
        `;
    }

    const investigation = report.investigation;

    return `
        <div class="report-investigation-grid">
            <div>
                <span>Alert</span>
                <strong>
                    ${escapeHtml(investigation.alert_id || "—")}
                </strong>
            </div>

            <div>
                <span>Severity</span>
                <strong>
                    ${escapeHtml(investigation.severity || "—")}
                </strong>
            </div>

            <div>
                <span>Disposition</span>
                <strong>
                    ${escapeHtml(
                        investigation.disposition ||
                        "Not assigned"
                    )}
                </strong>
            </div>

            <div>
                <span>Status</span>
                <strong>
                    ${escapeHtml(investigation.status || "New")}
                </strong>
            </div>

            <div>
                <span>Evidence events</span>
                <strong>
                    ${escapeHtml(investigation.evidence_count)}
                </strong>
            </div>
        </div>

        <div class="report-notes">
            <span>Analyst notes</span>
            <p>
                ${escapeHtml(
                    investigation.notes ||
                    "No analyst notes were recorded."
                )}
            </p>
        </div>
    `;
}


function renderReportReplay(report) {
    if (!report.replay) {
        return `
            <div class="report-optional-empty">
                No replay experiment is attached to this report snapshot.
                Run Detection Replay to include before/after tuning evidence.
            </div>
        `;
    }

    const replay = report.replay;

    const effectLabels = {
        fewer_alerts: "Fewer alerts",
        more_alerts: "More alerts",
        no_count_change: "No count change"
    };

    const changes = Object.entries(replay.changes || {});

    return `
        <div class="report-replay-summary">
            <div>
                <span>Rule</span>
                <strong>${escapeHtml(replay.rule_id)}</strong>
            </div>

            <div>
                <span>Baseline</span>
                <strong>${escapeHtml(replay.before)}</strong>
            </div>

            <div>
                <span>Tuned</span>
                <strong>${escapeHtml(replay.after)}</strong>
            </div>

            <div>
                <span>Effect</span>
                <strong>
                    ${escapeHtml(
                        effectLabels[replay.effect] ||
                        "Replay complete"
                    )}
                </strong>
            </div>

            <div>
                <span>Difference</span>
                <strong>
                    ${escapeHtml(
                        replay.difference > 0
                            ? `+${replay.difference}`
                            : replay.difference
                    )}
                </strong>
            </div>

            <div>
                <span>Events held constant</span>
                <strong>
                    ${escapeHtml(replay.telemetry_event_count)}
                </strong>
            </div>
        </div>

        ${
            changes.length
                ? `
                    <div class="report-change-list">
                        ${changes.map(([key, value]) => `
                            <div>
                                <span>
                                    ${escapeHtml(
                                        key
                                            .replaceAll("_", " ")
                                            .replace(
                                                /\b\w/g,
                                                letter =>
                                                    letter.toUpperCase()
                                            )
                                    )}
                                </span>
                                <strong>${escapeHtml(value)}</strong>
                            </div>
                        `).join("")}
                    </div>
                `
                : ""
        }
    `;
}


function renderReports() {
    if (!state.events.length) {
        workspace.innerHTML = `
            <div class="section-placeholder">
                <p class="eyebrow">REPORTING</p>
                <h3>No analysis available</h3>
                <p>
                    Load telemetry and run AlertCraft's detection pipeline
                    before generating an analysis report.
                </p>

                <button
                    class="button button-primary"
                    id="report-load-demo"
                    type="button"
                >
                    Load controlled demo
                </button>
            </div>
        `;

        document
            .getElementById("report-load-demo")
            .addEventListener("click", loadDemo);

        return;
    }

    const report = buildReportSnapshot();

    const previousReports =
        state.reports.length
            ? state.reports.slice(-3).reverse()
            : [];

    workspace.innerHTML = `
        <div class="reports-heading">
            <div>
                <p class="eyebrow">ANALYSIS OUTPUT</p>
                <h3>Security Analysis Report</h3>
                <p>
                    A report generated from AlertCraft's current telemetry,
                    detections and analyst workflow.
                </p>
            </div>

            <div class="report-actions">
                <button
                    class="button button-secondary"
                    id="save-report-snapshot"
                    type="button"
                >
                    Save snapshot
                </button>

                <button
                    class="button button-primary"
                    id="print-report"
                    type="button"
                >
                    Print / Save PDF
                </button>
            </div>
        </div>

        <article class="report-document" id="report-document">
            <header class="report-cover">
                <div>
                    <span class="report-brand">ALERTCRAFT</span>
                    <p>Detection Engineering & Investigation Lab</p>
                </div>

                <div class="report-meta">
                    <span>${escapeHtml(report.report_id)}</span>
                    <strong>
                        ${escapeHtml(
                            formatReportTimestamp(report.generated_at)
                        )}
                    </strong>
                </div>
            </header>

            <section class="report-title-block">
                <p class="eyebrow">SECURITY ANALYSIS</p>
                <h1>Detection & Investigation Report</h1>
                <p>
                    Generated from
                    <strong>${escapeHtml(report.source)}</strong>.
                    This report reflects the current AlertCraft analysis
                    snapshot and does not claim continuous monitoring.
                </p>
            </section>

            <section class="report-section">
                <div class="report-section-heading">
                    <div>
                        <p class="eyebrow">01 · EXECUTIVE SUMMARY</p>
                        <h2>Analysis overview</h2>
                    </div>
                </div>

                <div class="report-metrics">
                    <div>
                        <span>Events analyzed</span>
                        <strong>${report.event_count}</strong>
                    </div>

                    <div>
                        <span>Alerts generated</span>
                        <strong>${report.alert_count}</strong>
                    </div>

                    <div>
                        <span>Critical</span>
                        <strong>${report.severity.Critical}</strong>
                    </div>

                    <div>
                        <span>High</span>
                        <strong>${report.severity.High}</strong>
                    </div>
                </div>

                <div class="report-context-grid">
                    <div>
                        <span>Hosts observed</span>
                        <strong>${report.hosts.length}</strong>
                    </div>

                    <div>
                        <span>Users observed</span>
                        <strong>${report.users.length}</strong>
                    </div>

                    <div>
                        <span>Log sources</span>
                        <strong>${report.sources.length}</strong>
                    </div>

                    <div>
                        <span>Rules loaded</span>
                        <strong>${report.rules_loaded}</strong>
                    </div>
                </div>
            </section>

            <section class="report-section">
                <div class="report-section-heading">
                    <div>
                        <p class="eyebrow">02 · DETECTION FINDINGS</p>
                        <h2>Alerts generated</h2>
                    </div>

                    <span>${report.alert_count} findings</span>
                </div>

                <div class="report-table-wrap">
                    <table class="report-table">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Detection</th>
                                <th>Host</th>
                                <th>User</th>
                                <th>Risk</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>

                        <tbody>
                            ${renderReportAlertRows(report)}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="report-section">
                <div class="report-section-heading">
                    <div>
                        <p class="eyebrow">03 · MITRE ATT&CK</p>
                        <h2>Mapped techniques</h2>
                    </div>
                </div>

                <div class="report-mitre-grid">
                    ${renderReportMitre(report)}
                </div>
            </section>

            <section class="report-section">
                <div class="report-section-heading">
                    <div>
                        <p class="eyebrow">04 · ANALYST INVESTIGATION</p>
                        <h2>Current investigation context</h2>
                    </div>
                </div>

                ${renderReportInvestigation(report)}
            </section>

            <section class="report-section">
                <div class="report-section-heading">
                    <div>
                        <p class="eyebrow">05 · DETECTION REPLAY</p>
                        <h2>Tuning evidence</h2>
                    </div>
                </div>

                ${renderReportReplay(report)}
            </section>

            <footer class="report-footer">
                <div>
                    <strong>AlertCraft</strong>
                    <span>Detection Engineering & Investigation Lab</span>
                </div>

                <p>
                    Generated from the currently loaded analysis state.
                    Analyst decisions and report snapshots are session-local
                    unless exported.
                </p>
            </footer>
        </article>

        ${
            previousReports.length
                ? `
                    <section class="panel report-history">
                        <div class="panel-header">
                            <div>
                                <p class="eyebrow">CURRENT SESSION</p>
                                <h4>Saved snapshots</h4>
                            </div>

                            <span class="panel-count">
                                ${state.reports.length}
                            </span>
                        </div>

                        <div class="report-history-list">
                            ${previousReports.map(item => `
                                <div>
                                    <span>${escapeHtml(item.report_id)}</span>
                                    <strong>
                                        ${escapeHtml(
                                            formatReportTimestamp(
                                                item.generated_at
                                            )
                                        )}
                                    </strong>
                                    <small>
                                        ${item.event_count} events ·
                                        ${item.alert_count} alerts
                                    </small>
                                </div>
                            `).join("")}
                        </div>
                    </section>
                `
                : ""
        }
    `;

    document
        .getElementById("print-report")
        .addEventListener("click", () => {
            window.print();
        });

    document
        .getElementById("save-report-snapshot")
        .addEventListener("click", () => {
            const snapshot = buildReportSnapshot();

            state.reports.push(snapshot);

            if (state.reports.length > 10) {
                state.reports.shift();
            }

            showNotification(
                `Report snapshot ${snapshot.report_id} saved for this session.`
            );

            renderReports();
        });
}


function renderPlaceholder(title, description) {
    workspace.innerHTML = `
        <div class="section-placeholder">

            <p class="eyebrow">
                ALERTCRAFT WORKSPACE
            </p>

            <h3>
                ${escapeHtml(title)}
            </h3>

            <p>
                ${escapeHtml(description)}
            </p>

        </div>
    `;
}


function renderCurrentView() {
    if (state.view === "overview") {
        renderOverview();
        return;
    }

    if (
        state.view === "alerts"
        && state.investigation
    ) {
        renderInvestigation();
        return;
    }

    if (state.view === "telemetry") {
        renderTelemetry();
        return;
    }

    if (state.view === "rules") {
        renderRules();
        return;
    }

    if (state.view === "replay") {
        renderReplay();
        return;
    }

    if (state.view === "reports") {
        renderReports();
        return;
    }


    const placeholders = {
        alerts: [
            "Alert Investigation",
            "Evidence-backed alert triage and investigation will appear here."
        ],

        telemetry: [
            "Telemetry Explorer",
            "Normalized security events and raw evidence will appear here."
        ],

        rules: [
            "Detection Rules",
            "Detection logic, MITRE mappings and rule configuration will appear here."
        ],

        replay: [
            "Detection Replay",
            "Rule tuning and before/after replay comparison will appear here."
        ],

        reports: [
            "Reports",
            "Investigation and detection reports will appear here."
        ]
    };


    const content =
        placeholders[state.view];

    renderPlaceholder(
        content[0],
        content[1]
    );
}


async function loadDemo() {
    clearNotification();

    showNotification(
        "Running controlled telemetry through the detection engine..."
    );

    try {
        const data =
            await apiRequest(
                "/api/demo",
                {
                    method: "POST"
                }
            );

        state.events = data.events;
        state.alerts = data.alerts;
        state.source = data.source;
        state.replayResult = null;
        state.reports = [];

        updateDatasetLabel();

        showNotification(
            `${data.event_count} events analyzed. ${data.alert_count} alerts generated.`
        );

        state.view = "overview";

        activateNavigation("overview");

        pageTitle.textContent =
            "Overview";

        renderOverview();

    } catch (error) {
        showNotification(
            error.message,
            "error"
        );
    }
}


async function uploadTelemetry(file) {
    if (!file) {
        return;
    }

    clearNotification();

    const formData =
        new FormData();

    formData.append(
        "file",
        file
    );

    showNotification(
        "Analyzing uploaded telemetry..."
    );

    try {
        const data =
            await apiRequest(
                "/api/analyze",
                {
                    method: "POST",
                    body: formData
                }
            );

        state.events = data.events;
        state.alerts = data.alerts;
        state.source = data.source;
        state.replayResult = null;
        state.reports = [];

        updateDatasetLabel();

        showNotification(
            `${data.event_count} events analyzed. ${data.alert_count} alerts generated.`
        );

        state.view = "overview";

        activateNavigation("overview");

        pageTitle.textContent =
            "Overview";

        renderOverview();

    } catch (error) {
        showNotification(
            error.message,
            "error"
        );

    } finally {
        fileInput.value = "";
    }
}


function activateNavigation(view) {
    document
        .querySelectorAll(".nav-item")
        .forEach(item => {

            item.classList.toggle(
                "active",
                item.dataset.view === view
            );

        });
}


function selectView(view) {
    state.view = view;

    activateNavigation(view);

    const titles = {
        overview: "Overview",
        alerts: "Alerts",
        telemetry: "Telemetry",
        rules: "Detection Rules",
        replay: "Replay",
        reports: "Reports"
    };

    pageTitle.textContent =
        titles[view] || "AlertCraft";

    renderCurrentView();
}


document
    .querySelectorAll(".nav-item")
    .forEach(button => {

        button.addEventListener(
            "click",
            () => {
                selectView(
                    button.dataset.view
                );
            }
        );

    });


document
    .getElementById("load-demo-button")
    .addEventListener(
        "click",
        loadDemo
    );


document
    .getElementById("upload-button")
    .addEventListener(
        "click",
        () => fileInput.click()
    );


fileInput.addEventListener(
    "change",
    event => {
        uploadTelemetry(
            event.target.files[0]
        );
    }
);


async function initialize() {
    await Promise.all([
        checkHealth(),
        loadRules()
    ]);

    renderCurrentView();
}


initialize();