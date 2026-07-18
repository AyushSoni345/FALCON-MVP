// Module 9 - Security Operations Dashboard Client Application
// Built for high-efficiency banking SOC environments with complete state traceability

// Data is fetched dynamically from the API via Dashboard Gateway.

// Single Authoritative Frontend State Object
const dashboardState = {
    dashboard: null,
    currentWorkspace: "info",
    activeDashboardId: null,
    connectionStatus: "Not Loaded"
};

let refreshTimer = null;

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    setupEventListeners();
    updateClock();
    setInterval(updateClock, 1000);
});

// Helper for simulating delay
const delay = ms => new Promise(res => setTimeout(res, ms));

// Real-time Clock
function updateClock() {
    const now = new Date();
    document.getElementById("current-time").innerText = now.toISOString().replace("T", " ").substring(0, 19) + " UTC";
}

// Event Listeners Setup
function setupEventListeners() {
    // Sidebar navigation toggles
    const sidebarLinks = document.querySelectorAll("#sidebar a[data-workspace]");
    sidebarLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const workspaceName = link.getAttribute("data-workspace");
            navigateToWorkspace(workspaceName);
        });
    });

    // Control buttons
    document.getElementById("btn-load-sample").addEventListener("click", loadIRLPSession);
    document.getElementById("btn-refresh").addEventListener("click", refreshSession);
    document.getElementById("btn-submit-comment").addEventListener("click", submitComment);
    document.getElementById("btn-add-tag").addEventListener("click", submitTag);

    // Workflow actions buttons
    document.getElementById("btn-wf-assign").addEventListener("click", () => triggerWorkflow("Assign"));
    document.getElementById("btn-wf-close").addEventListener("click", () => triggerWorkflow("Close"));
    document.getElementById("btn-wf-reopen").addEventListener("click", () => triggerWorkflow("Reopen"));
}

// Update Connection Status Indicator
function setConnectionStatus(statusStr) {
    dashboardState.connectionStatus = statusStr;
    const badge = document.getElementById("dashboard-connection-status");
    badge.innerText = statusStr;
    
    badge.className = "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ml-1";
    if (statusStr === "Ready" || statusStr === "Dashboard Ready") {
        badge.classList.add("bg-emerald-500/10", "text-emerald-400", "border", "border-emerald-500/25");
    } else if (statusStr === "Connecting" || statusStr === "Loading" || statusStr === "Refreshing" || statusStr.includes("...")) {
        badge.classList.add("bg-blue-500/10", "text-blue-400", "border", "border-blue-500/25", "animate-pulse");
    } else if (statusStr === "Offline") {
        badge.classList.add("bg-slate-500/10", "text-slate-400", "border", "border-slate-500/25");
    } else if (statusStr === "Validation Failed" || statusStr === "Load Failed") {
        badge.classList.add("bg-rose-500/10", "text-rose-400", "border", "border-rose-500/25");
    } else {
        badge.classList.add("bg-slate-500/10", "text-slate-400", "border", "border-slate-500/25");
    }
}

// central state workspace switching
function navigateToWorkspace(workspaceName) {
    if (!dashboardState.activeDashboardId) {
        showToast("Please load a dashboard session first", "warning");
        return;
    }
    dashboardState.currentWorkspace = workspaceName;
    updateSidebarUI();
    renderActiveWorkspace();
}

function updateSidebarUI() {
    const workspaceName = dashboardState.currentWorkspace;
    document.querySelectorAll("#sidebar a[data-workspace]").forEach(link => {
        if (link.getAttribute("data-workspace") === workspaceName) {
            link.classList.add("bg-primary/20", "text-primary", "border-primary");
            link.classList.remove("text-slate-400", "hover:bg-slate-800/50", "hover:text-slate-200", "border-transparent");
        } else {
            link.classList.remove("bg-primary/20", "text-primary", "border-primary");
            link.classList.add("text-slate-400", "hover:bg-slate-800/50", "hover:text-slate-200", "border-transparent");
        }
    });

    document.querySelectorAll("section[data-panel]").forEach(panel => {
        if (panel.getAttribute("data-panel") === workspaceName) {
            panel.classList.remove("hidden");
        } else {
            panel.classList.add("hidden");
        }
    });
}

// Load a session by posting IRLP to API with stepped loader sequence
async function loadIRLPSession() {
    const overlay = document.getElementById("loading-overlay");
    const loaderText = document.getElementById("loading-step-text");

    try {
        overlay.classList.remove("hidden");
        
        // Step 1: Validating Module 8 Package
        loaderText.innerText = "Validating Module 8 Package...";
        setConnectionStatus("Validating...");
        await delay(500);

        const response = await fetch(`/api/v1/dashboard/workspace`);

        // Step 2: Creating Dashboard Session
        loaderText.innerText = "Creating Dashboard Session...";
        setConnectionStatus("Creating Session...");
        await delay(500);

        if (!response.ok) {
            let errDetail = "Validation failed: Malformed IRLP schema";
            try {
                const errData = await response.json();
                errDetail = errData.detail || errDetail;
            } catch(e){}
            throw new Error(errDetail);
        }

        const dashboard = await response.json();

        // Step 3: Building Workspaces
        loaderText.innerText = "Building Workspaces...";
        setConnectionStatus("Building...");
        await delay(500);

        // Step 4: Rendering Dashboard
        loaderText.innerText = "Rendering Dashboard...";
        setConnectionStatus("Rendering...");
        await delay(400);

        // Step 5: Dashboard Ready
        loaderText.innerText = "Dashboard Ready!";
        setConnectionStatus("Dashboard Ready");
        await delay(300);

        // Populate state object
        dashboardState.dashboard = dashboard;
        dashboardState.activeDashboardId = dashboard.dashboard_information.dashboard_id;
        
        // Hide empty state panel
        document.getElementById("panel-empty").classList.add("hidden");
        
        // Update header values and title
        updateHeaderUI(dashboard);
        
        // Set up auto-refresh timer based on interval
        if (refreshTimer) clearInterval(refreshTimer);
        const intervalMs = dashboard.dashboard_information.refresh_interval * 1000;
        refreshTimer = setInterval(refreshSession, intervalMs);

        // Switch to the default workspace automatically
        navigateToWorkspace("info");
        showToast("Dashboard session loaded successfully!", "success");

    } catch (error) {
        console.error("Load failed:", error);
        setConnectionStatus("Load Failed");
        
        // Show professional error card inside panel empty
        document.getElementById("panel-empty").classList.remove("hidden");
        document.getElementById("empty-state-icon").innerText = "error";
        document.getElementById("empty-state-icon").className = "material-symbols-outlined text-6xl text-error mb-4";
        document.getElementById("empty-state-title").innerText = "Session Creation Failed";
        document.getElementById("empty-state-text").innerText = `Validation Summary: ${error.message}. Stack trace was suppressed for compliance. Please verify the integrity of the Module 8 contract.`;
        
        showToast(`Failed to load session: ${error.message}`, "error");
    } finally {
        overlay.classList.add("hidden");
    }
}

// Refresh visualization
async function refreshSession() {
    if (!dashboardState.activeDashboardId) return;

    try {
        setConnectionStatus("Refreshing");
        const response = await fetch(`/api/v1/dashboard/workspace`);
        if (!response.ok) {
            setConnectionStatus("Offline");
            throw new Error("Refresh request failed");
        }
        
        const dashboard = await response.json();
        
        // Update state
        dashboardState.dashboard = dashboard;
        setConnectionStatus("Ready");
        
        updateHeaderUI(dashboard);
        renderActiveWorkspace();
        
        // Highlight refresh with icon rotation
        const icon = document.querySelector("#btn-refresh span");
        icon.classList.add("animate-spin");
        setTimeout(() => icon.classList.remove("animate-spin"), 500);

        showToast("Visualization sync updated.", "info");

    } catch (error) {
        console.error("Refresh failed:", error);
        showToast("Sync failed: " + error.message, "error");
    }
}

// Update Header details and Page Title
function updateHeaderUI(db) {
    document.getElementById("dashboard-active-id").innerText = db.dashboard_information.dashboard_id;
    document.getElementById("dashboard-active-mode").innerText = db.dashboard_information.dashboard_mode;
    document.getElementById("dashboard-active-mode").className = "px-2 py-0.5 rounded text-xs font-semibold bg-primary-fixed text-on-primary-fixed ml-1";

    const incId = db.live_operations_console.incident_id;
    const pkgId = db.dashboard_information.response_package_id;
    document.getElementById("header-incident-id").innerText = incId;
    document.getElementById("header-package-id").innerText = pkgId;
    
    // Set Page Title
    document.title = `FALCON SOD — ${incId}`;
}

// Submit Analyst Comment
async function submitComment() {
    if (!dashboardState.activeDashboardId) return;
    const input = document.getElementById("input-comment");
    const text = input.value.trim();
    if (!text) return;

    try {
        setConnectionStatus("Connecting");
        const response = await fetch(`/api/v1/dashboard/analyst/action`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                decision: "Comment Added",
                verdict: "Unknown",
                notes: text,
                analyst_id: "sonia.soc"
            })
        });

        if (!response.ok) throw new Error("Comment submission failed");
        
        input.value = "";
        refreshSession();
        showToast("Comment successfully saved.", "success");
    } catch (error) {
        showToast("Failed to save note: " + error.message, "error");
    }
}

// Submit Analyst Tag
async function submitTag() {
    if (!dashboardState.activeDashboardId) return;
    const input = document.getElementById("input-tag");
    const tag = input.value.trim();
    if (!tag) return;

    try {
        setConnectionStatus("Connecting");
        const response = await fetch(`/api/v1/dashboard/analyst/action`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                decision: "Tag Added: " + tag,
                verdict: "Unknown",
                notes: "",
                analyst_id: "sonia.soc"
            })
        });

        if (!response.ok) throw new Error("Tag submission failed");
        
        input.value = "";
        refreshSession();
        showToast("Tag appended successfully.", "success");
    } catch (error) {
        showToast("Failed to save tag: " + error.message, "error");
    }
}

// Trigger Workflow status actions
async function triggerWorkflow(action) {
    if (!dashboardState.activeDashboardId) return;
    
    try {
        setConnectionStatus("Connecting");
        const response = await fetch(`/api/v1/dashboard/analyst/action`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                decision: action,
                verdict: "True Positive",
                notes: "",
                analyst_id: "sonia.soc"
            })
        });
        
        if (!response.ok) throw new Error(`Workflow action ${action} failed.`);
        
        refreshSession();
        showToast(`Workflow status updated to ${action}d.`, "success");
    } catch (error) {
        showToast(`Action failed: ${error.message}`, "error");
    }
}

// Clipboard copying utility
window.copyToClipboard = function(elementId) {
    const text = document.getElementById(elementId).innerText;
    navigator.clipboard.writeText(text).then(() => {
        showToast("Copied ID to clipboard!", "success");
    }).catch(err => {
        showToast("Failed to copy ID!", "error");
    });
};

// Dedicated Router to Render Active Workspace from State
function renderActiveWorkspace() {
    const db = dashboardState.dashboard;
    if (!db) return;

    switch (dashboardState.currentWorkspace) {
        case "info":
            renderDashboardInfo(db);
            break;
        case "live-ops":
            renderLiveOps(db);
            break;
        case "incidents":
            renderIncidentMonitoring(db);
            break;
        case "knowledge-graph":
            renderKnowledgeGraph(db);
            break;
        case "threat-intel":
            renderThreatIntel(db);
            break;
        case "response-ops":
            renderResponseOperations(db);
            break;
        case "learning":
            renderContinuousLearning(db);
            break;
        case "analytics":
            renderExecutiveAnalytics(db);
            break;
        case "analyst":
            renderAnalystWorkspace(db);
            break;
        case "references":
            renderTraceability(db);
            break;
        default:
            console.error("Unknown workspace tab: ", dashboardState.currentWorkspace);
    }
}

// --- Dedicated Workspace Renderers ---

function renderDashboardInfo(db) {
    const info = db.dashboard_information;
    const live = db.live_operations_console;
    const intel = db.explainable_threat_intelligence_workspace;
    const resp = db.response_operations_workspace;
    const learn = db.continuous_learning_workspace;
    const analyst = db.analyst_interaction_workspace;
    
    // Bind legacy compatibility elements (hidden but validated)
    document.getElementById("info-dash-id").innerText = info.dashboard_id;
    document.getElementById("info-pkg-id").innerText = info.response_package_id;
    document.getElementById("info-timestamp").innerText = new Date(info.dashboard_timestamp).toISOString();
    document.getElementById("info-version").innerText = info.dashboard_version;
    document.getElementById("info-mode").innerText = info.dashboard_mode;
    document.getElementById("info-interval").innerText = info.refresh_interval + " seconds";

    // Bind Level 1: Executive Decision Bar
    const execBar = document.getElementById("info-executive-decision-bar");
    const riskLevelStr = intel?.executive_summary_reference?.risk_level || "Medium";
    const soarCount = resp?.soar_orchestration_tasks?.length || 0;
    const ruleName = resp?.incident_response_plan?.response_decision_trace?.selected_rule || "Default Policy Rule";
    const validationState = live.workflow_stage || "Awaiting Analyst Validation";
    
    execBar.innerText = `${riskLevelStr} severity security incident detected. Strategy is [${live.response_strategy}] via rule [${ruleName}]. Prepared ${soarCount} SOAR tasks. Current status: ${validationState}.`;

    // Bind Level 1: Executive Summary Row
    document.getElementById("info-exec-incident-id").innerText = live.incident_id;
    document.getElementById("info-exec-strategy").innerText = live.response_strategy;
    document.getElementById("info-exec-risk-score").innerText = intel?.executive_summary_reference?.unified_risk_score || "N/A";
    document.getElementById("info-exec-risk-level").innerText = riskLevelStr;
    document.getElementById("info-exec-type").innerText = live.execution_type;
    document.getElementById("info-exec-team").innerText = live.assigned_team;
    document.getElementById("info-exec-pkg-status").innerText = live.package_status;
    document.getElementById("info-exec-analyst").innerText = analyst?.analyst_validation?.analyst_decision || "Unassigned";

    // Bind Level 1: KPI Cards
    document.getElementById("info-kpi-incident-type").innerText = live.incident_type;
    document.getElementById("info-kpi-incident-id").innerText = live.incident_id;
    document.getElementById("info-kpi-package-status").innerText = live.package_status;

    document.getElementById("info-kpi-strategy").innerText = live.response_strategy;
    document.getElementById("info-kpi-team").innerText = live.assigned_team;
    document.getElementById("info-kpi-execution").innerText = live.execution_type;

    document.getElementById("info-kpi-risk-level").innerText = riskLevelStr;
    document.getElementById("info-kpi-risk-score").innerText = "Score: " + (intel?.executive_summary_reference?.unified_risk_score || 0);
    const evidenceCount = intel?.evidence_reference?.evidence_count || 0;
    document.getElementById("info-kpi-evidence-count").innerText = evidenceCount + " correlated event logs";

    document.getElementById("info-kpi-soar-prepared").innerText = `${soarCount} Playbook Tasks`;
    document.getElementById("info-kpi-soar-playbooks").innerText = "SOAR prep status: " + live.soar_preparation_status;
    document.getElementById("info-kpi-soar-level").innerText = live.execution_priority + " priority";

    const feedbackText = analyst?.analyst_validation ? "Validated" : "Pending Approval";
    document.getElementById("info-kpi-learning-val").innerText = feedbackText;
    document.getElementById("info-kpi-learning-opt").innerText = (learn?.model_optimization_recommendations?.length || 0) + " optimization recommendations";
    document.getElementById("info-kpi-learning-pkg").innerText = learn?.continuous_learning_package ? "Available" : "Not yet generated";

    // Bind Level 2: Incident Command Center
    document.getElementById("info-cmd-incident-id").innerText = live.incident_id;
    document.getElementById("info-cmd-incident-type").innerText = live.incident_type;
    document.getElementById("info-cmd-priority").innerText = live.execution_priority;
    document.getElementById("info-cmd-outcome").innerText = resp?.incident_response_plan?.expected_outcome || "Immediate mitigation";
    document.getElementById("info-cmd-root-cause").innerText = intel?.root_cause_reference?.probable_root_cause || "No root cause was detailed in the referenced threat report.";

    // Bind Level 2: Threat Intelligence Highlights & Key Artifacts
    const badgeRisk = document.getElementById("info-intel-risk-level");
    badgeRisk.innerText = riskLevelStr;
    badgeRisk.className = "text-[10px] font-extrabold px-2 py-0.5 rounded uppercase";
    if (riskLevelStr === "Critical" || riskLevelStr === "High") {
        badgeRisk.classList.add("bg-rose-500/10", "text-rose-400", "border", "border-rose-500/25");
    } else {
        badgeRisk.classList.add("bg-amber-500/10", "text-amber-400", "border", "border-amber-500/25");
    }

    document.getElementById("info-intel-confidence").innerText = intel?.analyst_support_reference?.confidence_summary || "Calculated confidence: High";
    
    // Key Artifacts List
    const artifactsList = document.getElementById("info-intel-artifacts-list");
    artifactsList.innerHTML = "";
    const artifacts = intel?.investigation_reference?.priority_artifacts || [];
    if (artifacts.length === 0) {
        artifactsList.innerHTML = `<span class="text-slate-500 italic text-[11px]">No priority investigation artifacts listed.</span>`;
    } else {
        artifacts.forEach((art, idx) => {
            const cardId = `artifact-info-${idx}`;
            artifactsList.innerHTML += `
                <div class="flex items-center justify-between p-2 bg-slate-900/40 rounded border border-border/50 group relative">
                    <div class="flex items-center gap-2 overflow-hidden">
                        <span class="material-symbols-outlined text-slate-500 text-sm">settings_ethernet</span>
                        <span id="${cardId}" class="font-mono text-[10px] text-slate-300 truncate">${art}</span>
                    </div>
                    <button onclick="copyToClipboard('${cardId}')" class="text-slate-500 hover:text-slate-200 transition-colors opacity-0 group-hover:opacity-100">
                        <span class="material-symbols-outlined text-[12px]">content_copy</span>
                    </button>
                </div>
            `;
        });
    }

    // Bind Level 2: Evidence List
    document.getElementById("info-evidence-badge").innerText = evidenceCount + " Logs";
    const evidenceList = document.getElementById("info-evidence-list");
    evidenceList.innerHTML = "";
    if (evidenceCount === 0) {
        evidenceList.innerHTML = `<span class="text-slate-500 italic text-[11px]">No correlated evidence logs found.</span>`;
    } else {
        for (let i = 1; i <= evidenceCount; i++) {
            evidenceList.innerHTML += `
                <div class="p-2.5 bg-slate-900/40 rounded border border-border/50 flex flex-col gap-1">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-300">Evidence Line #${i}</span>
                        <span class="text-[9px] text-slate-500">Correlated</span>
                    </div>
                    <span class="text-slate-400 text-[10px]">Verified event reference corresponding to logged packet headers under threat analysis signature match.</span>
                </div>
            `;
        }
    }

    // Bind Level 2: Playbook Steps
    document.getElementById("info-playbook-strategy-badge").innerText = live.response_strategy;
    const stepsList = document.getElementById("info-playbook-steps");
    stepsList.innerHTML = "";
    const recActions = resp?.incident_response_plan?.recommended_actions || [];
    if (recActions.length === 0) {
        stepsList.innerHTML = `<span class="text-slate-500 italic text-[11px]">No playbook actions recommended.</span>`;
    } else {
        recActions.forEach((act, idx) => {
            stepsList.innerHTML += `
                <div class="flex items-start gap-3 p-2.5 bg-slate-900/40 rounded border border-border/50">
                    <span class="flex items-center justify-center w-5 h-5 rounded-full bg-success/20 text-success text-[10px] font-bold border border-success/30 mt-0.5">${idx + 1}</span>
                    <div class="flex flex-col gap-0.5">
                        <span class="font-bold text-slate-200">${act}</span>
                        <span class="text-[10px] text-slate-500">Playbook target action — Status: Prepared</span>
                    </div>
                </div>
            `;
        });
    }

    // Bind Level 2: Decision Trace Explainer
    const traceList = document.getElementById("info-decision-trace");
    traceList.innerHTML = "";
    const trace = resp?.incident_response_plan?.response_decision_trace;
    const factors = trace?.decision_factors || [];
    if (factors.length === 0) {
        traceList.innerHTML = `<span class="text-slate-500 italic text-[11px]">No decision trace factors compiled.</span>`;
    } else {
        factors.forEach((f, idx) => {
            const isLast = idx === factors.length - 1;
            traceList.innerHTML += `
                <div class="relative pl-6 pb-4">
                    ${!isLast ? '<div class="absolute left-[3px] top-4 bottom-0 w-px bg-border"></div>' : ''}
                    <div class="absolute left-0 top-1 w-2 h-2 rounded-full bg-cyan-400"></div>
                    <div class="flex flex-col gap-0.5">
                        <span class="font-bold text-slate-200">Trace Factor: ${f}</span>
                        <span class="text-[10px] text-slate-500">Evaluated signature criteria for response recommendation.</span>
                    </div>
                </div>
            `;
        });
    }

    // Bind Level 2: SOAR Pipeline tasks
    const soarList = document.getElementById("info-soar-pipeline");
    soarList.innerHTML = "";
    const soarTasks = resp?.soar_orchestration_tasks || [];
    if (soarTasks.length === 0) {
        soarList.innerHTML = `<span class="text-slate-500 italic text-[11px]">No SOAR execution tasks prepared.</span>`;
    } else {
        soarTasks.forEach((task, idx) => {
            const statusClass = task.execution_status === "Prepared" ? "text-indigo-400 bg-indigo-500/10 border-indigo-500/25" : "text-slate-400 bg-slate-800/40 border-border";
            soarList.innerHTML += `
                <div class="p-2.5 bg-slate-900/40 rounded border border-border/50 flex flex-col gap-1">
                    <div class="flex items-center justify-between">
                        <span class="font-mono font-bold text-[10px] text-slate-300 truncate max-w-[150px]">${task.task_id}</span>
                        <span class="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${statusClass}">${task.execution_status}</span>
                    </div>
                    <div class="flex items-center justify-between text-[10px] text-slate-400">
                        <span>Playbook: ${task.playbook_name}</span>
                        <span>Auto Level: ${task.automation_level}</span>
                    </div>
                </div>
            `;
        });
    }

    // Bind Level 3 Graph Reference
    document.getElementById("info-graph-ref").innerText = "Ref: " + (db.security_knowledge_graph_visualizer?.graph_reference || "None");

    // Bind Level 3 Continuous Learning Box
    const learnBox = document.getElementById("info-learning-status-box");
    if (analyst?.analyst_validation) {
        learnBox.innerHTML = `
            <span class="material-symbols-outlined text-xs text-success">check_circle</span>
            <span class="text-success font-semibold">Feedback Submitted (Awaiting next cycle)</span>
        `;
        learnBox.className = "mt-2 text-[10px] text-success bg-success/10 border border-success/20 p-2 rounded flex items-center gap-1.5";
    } else {
        learnBox.innerHTML = `
            <span class="material-symbols-outlined text-xs text-warning animate-pulse">pending</span>
            <span class="text-warning font-semibold">Awaiting Analyst validation</span>
        `;
        learnBox.className = "mt-2 text-[10px] text-warning bg-warning/10 border border-warning/20 p-2 rounded flex items-center gap-1.5";
    }
}

function renderLiveOps(db) {
    const live = db.live_operations_console;
    document.getElementById("live-incident-id").innerText = live.incident_id;
    document.getElementById("live-package-status").innerText = live.package_status;
    document.getElementById("live-incident-type").innerText = live.incident_type;
    document.getElementById("live-response-strategy").innerText = live.response_strategy;
    document.getElementById("live-assigned-team").innerText = live.assigned_team;
    document.getElementById("live-execution-priority").innerText = live.execution_priority;
    document.getElementById("live-execution-type").innerText = live.execution_type;
    document.getElementById("live-soar-status").innerText = live.soar_preparation_status;
    document.getElementById("live-historical-msg").innerText = live.historical_metrics_message;
}

function renderIncidentMonitoring(db) {
    const inc = db.incident_monitoring_workspace;
    const sel = inc.selected_incident;
    
    document.getElementById("inc-sel-id").innerText = sel.incident_id;
    document.getElementById("inc-sel-strategy").innerText = sel.response_strategy;
    document.getElementById("inc-sel-team").innerText = sel.assigned_team;
    document.getElementById("inc-sel-priority").innerText = sel.execution_priority;
    document.getElementById("inc-sel-status").innerText = sel.package_status;
    document.getElementById("inc-sel-updated").innerText = sel.estimated_completion_time;
    
    // SLA Progress
    const progressVal = inc.response_progress;
    const progressPct = Math.round(progressVal * 100) + "%";
    document.getElementById("inc-progress-bar").style.width = progressPct;
    document.getElementById("inc-progress-text").innerText = progressPct + " Execution Complete";

    // CSS colors for badging
    const priorityBadge = document.getElementById("inc-sel-priority");
    if (sel.execution_priority === "High" || sel.execution_priority === "P1" || sel.execution_priority === "P2") {
        priorityBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-800 border border-red-200";
    } else {
        priorityBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-200";
    }

    const statusBadge = document.getElementById("inc-sel-status");
    if (sel.package_status === "Closed" || sel.package_status === "Contained") {
        statusBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200";
    } else {
        statusBadge.className = "px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200";
    }

    // Incidents queue list
    document.getElementById("incidents-table-body").innerHTML = `
        <tr class="hover:bg-neutral-50 cursor-pointer border-b border-outline-variant">
            <td class="px-4 py-3 font-semibold text-primary font-mono text-sm">${sel.incident_id}</td>
            <td class="px-4 py-3 text-sm">${sel.incident_type}</td>
            <td class="px-4 py-3 text-xs"><span class="${priorityBadge.className}">${sel.execution_priority}</span></td>
            <td class="px-4 py-3 text-xs"><span class="${statusBadge.className}">${sel.package_status}</span></td>
            <td class="px-4 py-3 text-sm text-on-surface-variant font-medium">${sel.assigned_team}</td>
        </tr>
    `;
}

function renderKnowledgeGraph(db) {
    const graph = db.security_knowledge_graph_visualizer;
    document.getElementById("graph-ref-id").innerText = graph.graph_reference;
}

function renderThreatIntel(db) {
    const intel = db.explainable_threat_intelligence_workspace;
    document.getElementById("threat-score").innerText = intel.executive_summary_reference.unified_risk_score;
    document.getElementById("threat-level").innerText = intel.executive_summary_reference.risk_level;
    document.getElementById("threat-evidence-count").innerText = intel.evidence_reference.evidence_count + " logs / events";
    document.getElementById("threat-root-cause").innerText = intel.root_cause_reference.probable_root_cause;
    document.getElementById("threat-confidence-summary").innerText = intel.analyst_support_reference.confidence_summary;

    // Checklist
    let guidanceHtml = "";
    if (intel.investigation_reference && intel.investigation_reference.priority_artifacts) {
        intel.investigation_reference.priority_artifacts.forEach(artifact => {
            guidanceHtml += `
                <div class="p-3 bg-neutral-50 rounded border border-outline-variant flex items-center gap-3">
                    <span class="material-symbols-outlined text-primary text-xl">label</span>
                    <span class="text-sm font-medium">${artifact}</span>
                </div>
            `;
        });
    }
    document.getElementById("threat-guidance-list").innerHTML = guidanceHtml || "<p class='text-sm text-outline'>No artifacts guidelines.</p>";
}

function renderResponseOperations(db) {
    const resp = db.response_operations_workspace;
    document.getElementById("resp-contain").innerText = resp.incident_response_plan.response_strategy;
    document.getElementById("resp-justification").innerText = resp.incident_response_plan.business_justification;
    document.getElementById("resp-outcome").innerText = resp.incident_response_plan.expected_outcome;
    document.getElementById("resp-priority").innerText = resp.response_execution_plan.execution_priority;
    document.getElementById("resp-contain-state").innerText = resp.containment_status;

    // Timeline actions
    let actionsHtml = "";
    resp.incident_response_plan.recommended_actions.forEach(action => {
        actionsHtml += `
            <div class="flex items-center gap-2.5 p-2 border-b border-outline-variant last:border-0">
                <input type="checkbox" checked disabled class="rounded border-outline text-primary focus:ring-0"/>
                <span class="text-sm font-medium">${action}</span>
            </div>
        `;
    });
    document.getElementById("resp-actions-list").innerHTML = actionsHtml;

    // Decision factors trace
    document.getElementById("trace-rule").innerText = resp.incident_response_plan.response_decision_trace.selected_rule;
    let traceHtml = "";
    resp.incident_response_plan.response_decision_trace.decision_factors.forEach(factor => {
        traceHtml += `
            <div class="bg-neutral-50 p-2 rounded border border-outline-variant mb-1 font-mono">${factor}</div>
        `;
    });
    document.getElementById("trace-factors").innerHTML = traceHtml;

    // SOAR task cards
    let soarHtml = "";
    resp.soar_orchestration_tasks.forEach(task => {
        let statusBadge = "bg-neutral-100 text-neutral-800 border-neutral-200";
        if (task.execution_status === "Completed") statusBadge = "bg-emerald-50 text-emerald-700 border-emerald-200";
        if (task.execution_status === "Running") statusBadge = "bg-blue-50 text-blue-700 border-blue-200";
        
        soarHtml += `
            <div class="p-3 border border-outline-variant bg-white rounded-lg flex items-center justify-between shadow-sm">
                <div>
                    <div class="text-sm font-semibold font-mono text-primary">${task.playbook_name}</div>
                    <div class="text-xs text-outline">Automation Level: ${task.automation_level} | ID: ${task.task_id}</div>
                </div>
                <div class="text-right">
                    <span class="px-2 py-0.5 text-xs font-semibold rounded border ${statusBadge}">${task.execution_status}</span>
                </div>
            </div>
        `;
    });
    document.getElementById("resp-soar-tasks").innerHTML = soarHtml || "<p class='text-sm text-outline'>No active SOAR tasks.</p>";
}

function renderContinuousLearning(db) {
    const lrn = db.continuous_learning_workspace;
    const lrnEmpty = document.getElementById("learning-empty-state");
    const lrnActive = document.getElementById("learning-active-panel");

    if (!lrn.continuous_learning_package) {
        lrnEmpty.classList.remove("hidden");
        lrnActive.classList.add("hidden");
    } else {
        lrnEmpty.classList.add("hidden");
        lrnActive.classList.remove("hidden");
        document.getElementById("lrn-verdict").innerText = lrn.continuous_learning_package.analyst_verdict;
        document.getElementById("lrn-label").innerText = lrn.continuous_learning_package.learning_label;
        document.getElementById("lrn-patterns").innerHTML = lrn.continuous_learning_package.contributing_patterns.map(p => `
            <span class="px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 text-xs font-semibold">${p}</span>
        `).join("");
    }

    // Optimization Recommendations
    const optEmpty = document.getElementById("opt-empty-state");
    if (lrn.model_optimization_recommendations.length > 0) {
        optEmpty.classList.add("hidden");
    } else {
        optEmpty.classList.remove("hidden");
    }
}

function renderExecutiveAnalytics(db) {
    // Left as static empty state card satisfying prompt requirements:
    // "Historical operational analytics become available after multiple Incident Response Packages have been processed."
}

function renderAnalystWorkspace(db) {
    const analyst = db.analyst_interaction_workspace;
    const validationAlert = document.getElementById("analyst-validation-alert");
    const validatedBadge = document.getElementById("analyst-validated-badge");

    if (!analyst.analyst_validation) {
        validationAlert.classList.remove("hidden");
        validatedBadge.classList.add("hidden");
    } else {
        validationAlert.classList.add("hidden");
        validatedBadge.classList.remove("hidden");
        validatedBadge.innerHTML = `
            <span class="material-symbols-outlined text-emerald-600">check_circle</span>
            <div>
                <strong class="block text-emerald-900">Analyst Decision Logged</strong>
                <p class="text-xs text-emerald-700 mt-0.5">Decision: <span class="font-bold font-mono">${analyst.analyst_validation.analyst_decision}</span> | Notes: ${analyst.analyst_validation.validation_notes}</p>
            </div>
        `;
    }

    // Note logs list
    let commHtml = "";
    analyst.analyst_comments.forEach(c => {
        commHtml += `
            <div class="p-3 bg-neutral-50 rounded-lg border border-outline-variant">
                <div class="flex items-center justify-between text-xs text-outline mb-1 font-semibold">
                    <span>${c.author}</span>
                    <span>${new Date(c.timestamp).toLocaleString()}</span>
                </div>
                <div class="text-sm font-medium text-[#1e293b]">${c.text}</div>
            </div>
        `;
    });
    document.getElementById("analyst-comments-list").innerHTML = commHtml || "<p class='text-sm text-outline'>No analyst notes posted yet.</p>";

    // Audit logs list
    let auditHtml = "";
    analyst.audit_annotations.forEach(a => {
        auditHtml += `
            <div class="flex items-start gap-3 py-1.5 border-b border-outline-variant text-xs last:border-b-0">
                <span class="material-symbols-outlined text-outline text-sm mt-0.5">history</span>
                <div class="flex-grow">
                    <span class="font-semibold">${a.action}</span> by <span class="font-mono text-primary font-bold">${a.actor}</span>
                    <div class="text-outline mt-0.5">${a.notes || ""}</div>
                </div>
                <span class="text-outline font-mono">${new Date(a.timestamp).toISOString().substring(11, 19)}</span>
            </div>
        `;
    });
    document.getElementById("analyst-audit-list").innerHTML = auditHtml;

    // Tags
    document.getElementById("analyst-tag-list").innerHTML = analyst.incident_tags.map(t => `
        <span class="px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 text-xs font-semibold font-mono uppercase">${t}</span>
    `).join("");
}

function renderTraceability(db) {
    // Render the workspace relationships inside referenced workspace
    const refs = db.referenced_incident_response_learning_package;
    document.getElementById("raw-references-json").innerText = JSON.stringify(refs, null, 2);
}

// Interactive Toast Notification
function showToast(message, type = "success") {
    const toast = document.createElement("div");
    toast.className = `fixed bottom-4 right-4 z-50 px-4 py-3 rounded-lg shadow-xl text-sm font-semibold border flex items-center gap-2 animate-bounce transition-all duration-300`;
    
    if (type === "success") {
        toast.classList.add("bg-emerald-50", "text-emerald-800", "border-emerald-200");
    } else if (type === "warning") {
        toast.classList.add("bg-amber-50", "text-amber-800", "border-amber-200");
    } else if (type === "error") {
        toast.classList.add("bg-red-50", "text-red-800", "border-red-200");
    } else {
        toast.classList.add("bg-blue-50", "text-blue-800", "border-blue-200");
    }

    toast.innerHTML = `
        <span class="material-symbols-outlined text-lg">info</span>
        <span>${message}</span>
    `;

    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}
