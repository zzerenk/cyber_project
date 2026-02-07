document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const targetInput = document.getElementById('targetInput');
    const resultArea = document.getElementById('resultArea');
    const terminalConsole = document.getElementById('terminalConsole');

    // Terminal logger
    function logToTerminal(message, type = 'info') {
        if (!terminalConsole) return;
        terminalConsole.classList.add('active');
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = message;
        terminalConsole.appendChild(line);
        terminalConsole.scrollTop = terminalConsole.scrollHeight;
    }

    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();

        // Collect options
        const options = {
            serviceVersion: document.getElementById('optSv').checked,
            detectOS: document.getElementById('optOs').checked,
            vulnScan: document.getElementById('optVuln').checked,
            speed: document.querySelector('input[name="speedOpt"]:checked').value
        };

        if (!target) {
            alert("Target system required!");
            return;
        }

        // Lock UI
        scanBtn.disabled = true;
        resultArea.style.display = 'none';
        resultArea.innerHTML = '';

        // Clear terminal and start logging
        terminalConsole.innerHTML = '';
        logToTerminal('[SYSTEM] Initializing scan module...', 'info');
        logToTerminal(`[TARGET] ${target}`, 'info');
        logToTerminal('[CONFIG] Preparing scan parameters...', 'info');

        try {
            // 1. START REQUEST: Initialize Task
            logToTerminal('[REQUEST] Sending scan request to API...', 'info');
            const startResponse = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target, options: options })
            });
            const startData = await startResponse.json();

            if (startData.success) {
                logToTerminal(`[SUCCESS] Task created: ${startData.task_id.substring(0, 8)}...`, 'success');
                logToTerminal('[SCANNER] Nmap engine starting...', 'info');
                // 2. START POLLING: Check every 2 seconds
                pollStatus(startData.task_id);
            } else {
                throw new Error(startData.error);
            }

        } catch (error) {
            logToTerminal(`[ERROR] ${error.message}`, 'error');
            resultArea.innerHTML = `<div class="alert alert-danger">Error: ${error.message}</div>`;
            scanBtn.disabled = false;
        }
    });

    // Status Polling Function (UNCHANGED LOGIC)
    async function pollStatus(taskId) {
        let scanPhase = 0;
        const phases = [
            '[*] Resolving target hostname...',
            '[*] Initiating port scan...',
            '[*] Analyzing open ports...',
            '[*] Probing service versions...',
            '[*] Performing OS detection...',
            '[*] Running vulnerability scripts...',
            '[*] Compiling scan results...'
        ];

        const intervalId = setInterval(async () => {
            try {
                const res = await fetch(`/api/status/${taskId}`);
                const data = await res.json();

                // Log phase progression
                if (scanPhase < phases.length && data.status === 'running') {
                    logToTerminal(phases[scanPhase], 'info');
                    scanPhase++;
                }

                // Scan completed
                if (data.status === 'completed') {
                    clearInterval(intervalId);
                    logToTerminal('[COMPLETE] Scan finished successfully', 'success');
                    logToTerminal('[RENDER] Generating dashboard...', 'info');
                    renderDashboard(data.result);
                    scanBtn.disabled = false;
                }
                else if (data.status === 'failed') {
                    clearInterval(intervalId);
                    logToTerminal(`[FAILED] ${data.message}`, 'error');
                    resultArea.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
                    scanBtn.disabled = false;
                }

            } catch (e) {
                clearInterval(intervalId);
                logToTerminal(`[ERROR] Polling failed: ${e.message}`, 'error');
                console.error("Polling error:", e);
            }
        }, 2000); // Poll every 2 seconds
    }

    // --- ENHANCED DASHBOARD RENDERING ---
    function renderDashboard(data) {
        // 1. Calculate Risk Score
        const riskScore = calculateRiskScore(data);

        // 2. OS Detection
        let osHtml = '<span style="color: #9ca3af;">Not Detected</span>';
        let osIcon = '❓';
        let osClass = 'unknown';

        if (data.os_match && data.os_match.length > 0) {
            const os = data.os_match[0];
            osHtml = `<strong>${os.name}</strong> <span class="badge" style="background: #f59e0b; color: #000; font-size: 11px; padding: 3px 8px; border-radius: 4px;">${os.accuracy}% Confidence</span>`;

            if (os.name.toLowerCase().includes('windows')) {
                osIcon = '🪟';
                osClass = 'windows';
            } else if (os.name.toLowerCase().includes('linux')) {
                osIcon = '🐧';
                osClass = 'linux';
            } else {
                osIcon = '💻';
                osClass = 'other';
            }
        }

        // 3. Port Table
        let portsHtml = '';
        let portCount = 0;
        if (data.full_data && data.full_data.tcp) {
            for (const [port, details] of Object.entries(data.full_data.tcp)) {
                portCount++;
                portsHtml += `
                    <tr>
                        <td><span class="badge" style="background: #00f2ff; color: #000; font-weight: 600;">${port}</span></td>
                        <td>${details.name || 'Unknown'}</td>
                        <td style="font-family: 'Roboto Mono', monospace; font-size: 12px;">${details.product || ''} ${details.version || ''}</td>
                        <td><span class="badge" style="background: #10b981; color: #000;">${details.state.toUpperCase()}</span></td>
                    </tr>`;
            }
        } else {
            portsHtml = '<tr><td colspan="4" style="text-align: center; color: #9ca3af;">No open ports detected</td></tr>';
        }

        // 4. Vulnerabilities with Pagination
        const vulnContent = renderVulnerabilities(data.vulnerabilities);

        // 5. Main Dashboard HTML
        resultArea.style.display = 'block';
        resultArea.innerHTML = `
            <style>
                .dashboard-card {
                    background: #111827;
                    border: 1px solid #374151;
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 15px rgba(0, 0, 0, 0.3);
                }
                
                .overview-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 20px;
                    margin-bottom: 25px;
                }
                
                .metric-card {
                    background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
                    border: 1px solid #374151;
                    border-radius: 10px;
                    padding: 20px;
                    text-align: center;
                    transition: all 0.3s ease;
                }
                
                .metric-card:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 4px 15px rgba(0, 242, 255, 0.1);
                    border-color: #00f2ff;
                }
                
                .metric-label {
                    font-size: 12px;
                    color: #9ca3af;
                    text-transform: uppercase;
                    letter-spacing: 1px;
                    margin-bottom: 10px;
                }
                
                .metric-value {
                    font-size: 32px;
                    font-weight: 700;
                    color: #00f2ff;
                    margin-bottom: 5px;
                }
                
                .metric-icon {
                    font-size: 40px;
                    margin-bottom: 10px;
                }
                
                .tabs-container {
                    background: #111827;
                    border: 1px solid #374151;
                    border-radius: 12px;
                    overflow: hidden;
                }
                
                .tab-header {
                    display: flex;
                    background: #1f2937;
                    border-bottom: 1px solid #374151;
                }
                
                .tab-button {
                    flex: 1;
                    padding: 15px 20px;
                    background: transparent;
                    border: none;
                    color: #9ca3af;
                    cursor: pointer;
                    font-weight: 500;
                    font-size: 14px;
                    transition: all 0.3s ease;
                    border-right: 1px solid #374151;
                }
                
                .tab-button:last-child {
                    border-right: none;
                }
                
                .tab-button:hover {
                    background: rgba(0, 242, 255, 0.05);
                    color: #00f2ff;
                }
                
                .tab-button.active {
                    background: rgba(0, 242, 255, 0.1);
                    color: #00f2ff;
                    border-bottom: 2px solid #00f2ff;
                }
                
                .tab-content {
                    padding: 25px;
                }
                
                .tab-pane {
                    display: none;
                }
                
                .tab-pane.active {
                    display: block;
                }
                
                .data-table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 14px;
                }
                
                .data-table thead {
                    background: #1f2937;
                }
                
                .data-table th {
                    padding: 12px 15px;
                    text-align: left;
                    color: #00f2ff;
                    font-weight: 600;
                    text-transform: uppercase;
                    font-size: 12px;
                    letter-spacing: 0.5px;
                    border-bottom: 2px solid #374151;
                }
                
                .data-table td {
                    padding: 12px 15px;
                    border-bottom: 1px solid #374151;
                    color: #f3f4f6;
                }
                
                .data-table tr:hover {
                    background: rgba(0, 242, 255, 0.03);
                }
                
                .risk-score {
                    font-size: 48px;
                    font-weight: 700;
                }
                
                .risk-low { color: #10b981; }
                .risk-medium { color: #f59e0b; }
                .risk-high { color: #ef4444; }
                .risk-critical { color: #dc2626; }
            </style>
            
            <div class="overview-grid">
                <div class="metric-card">
                    <div class="metric-label">Target System</div>
                    <div class="metric-value" style="font-size: 24px; font-family: 'Roboto Mono', monospace;">${data.target ? data.target.ip : data.ip}</div>
                    <div style="color: #9ca3af; font-size: 13px; margin-top: 5px;">${data.hostname || 'No hostname'}</div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-label">Operating System</div>
                    <div class="metric-icon">${osIcon}</div>
                    <div style="font-size: 14px; color: #f3f4f6;">${osHtml}</div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-label">Open Ports</div>
                    <div class="metric-value">${portCount}</div>
                    <div style="color: #9ca3af; font-size: 13px;">Active Services</div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-label">Risk Assessment</div>
                    <div class="risk-score ${riskScore.class}">${riskScore.score}</div>
                    <div style="color: #9ca3af; font-size: 13px; text-transform: uppercase; letter-spacing: 1px;">${riskScore.level}</div>
                </div>
            </div>
            
            <div class="tabs-container">
                <div class="tab-header">
                    <button class="tab-button active" data-tab="ports">Port Analysis</button>
                    <button class="tab-button" data-tab="vulns">Vulnerabilities</button>
                    <button class="tab-button" data-tab="raw">Raw Data</button>
                </div>
                
                <div class="tab-content">
                    <div class="tab-pane active" id="tab-ports">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>Version</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>${portsHtml}</tbody>
                        </table>
                    </div>
                    
                    <div class="tab-pane" id="tab-vulns">
                        ${vulnContent}
                    </div>
                    
                    <div class="tab-pane" id="tab-raw">
                        <pre style="background: #000; color: #10b981; padding: 20px; border-radius: 8px; overflow: auto; max-height: 500px; font-family: 'Roboto Mono', monospace; font-size: 12px;">${JSON.stringify(data, null, 2)}</pre>
                    </div>
                </div>
            </div>
        `;

        // Tab switching logic
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                const tabName = button.getAttribute('data-tab');

                // Update buttons
                document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');

                // Update panes
                document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
                document.getElementById(`tab-${tabName}`).classList.add('active');
            });
        });
    }

    // Calculate Risk Score based on vulnerabilities
    function calculateRiskScore(data) {
        let score = 0;
        let level = 'LOW';
        let cssClass = 'risk-low';

        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            data.vulnerabilities.forEach(vuln => {
                if (vuln.parsed_data && vuln.parsed_data.length > 0) {
                    vuln.parsed_data.forEach(item => {
                        score += item.score || 0;
                        if (item.is_exploit) score += 5; // Extra weight for exploits
                    });
                }
            });

            // Average score
            const avgScore = score / Math.max(1, data.vulnerabilities.reduce((acc, v) => acc + (v.parsed_data?.length || 0), 0));

            if (avgScore >= 9.0) {
                level = 'CRITICAL';
                cssClass = 'risk-critical';
                score = Math.round(avgScore * 10);
            } else if (avgScore >= 7.0) {
                level = 'HIGH';
                cssClass = 'risk-high';
                score = Math.round(avgScore * 10);
            } else if (avgScore >= 4.0) {
                level = 'MEDIUM';
                cssClass = 'risk-medium';
                score = Math.round(avgScore * 10);
            } else {
                level = 'LOW';
                cssClass = 'risk-low';
                score = Math.round(avgScore * 10);
            }
        } else {
            score = 0;
            level = 'MINIMAL';
            cssClass = 'risk-low';
        }

        return { score, level, class: cssClass };
    }

    // Render Vulnerabilities with Pagination
    function renderVulnerabilities(vulnerabilities) {
        if (!vulnerabilities || vulnerabilities.length === 0) {
            return `
                <div style="text-align: center; padding: 60px 20px;">
                    <div style="font-size: 64px; margin-bottom: 20px;">✓</div>
                    <h3 style="color: #10b981; font-size: 24px; margin-bottom: 10px;">System Clean</h3>
                    <p style="color: #9ca3af;">No known vulnerabilities detected in current scan configuration</p>
                </div>
            `;
        }

        let html = '<div class="vuln-container">';

        vulnerabilities.forEach((vuln, vulnIndex) => {
            if (vuln.parsed_data && vuln.parsed_data.length > 0) {
                // Paginated view for parsed vulnerabilities
                const itemsPerPage = 5;
                const totalPages = Math.ceil(vuln.parsed_data.length / itemsPerPage);
                const containerId = `vuln-${vulnIndex}`;

                html += `
                    <div class="vuln-section" style="margin-bottom: 30px;">
                        <div style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); padding: 15px 20px; border-radius: 8px 8px 0 0; border: 1px solid #ef4444;">
                            <h4 style="margin: 0; color: #fff; font-size: 16px; font-weight: 600;">
                                ⚠ Port ${vuln.port} - Detected Vulnerabilities (${vuln.parsed_data.length})
                            </h4>
                        </div>
                        <div id="${containerId}" style="background: #1f2937; border: 1px solid #374151; border-top: none; border-radius: 0 0 8px 8px; padding: 20px;">
                `;

                // Group items into pages
                for (let page = 0; page < totalPages; page++) {
                    const start = page * itemsPerPage;
                    const end = Math.min(start + itemsPerPage, vuln.parsed_data.length);
                    const pageItems = vuln.parsed_data.slice(start, end);

                    html += `<div class="vuln-page" data-page="${page}" style="display: ${page === 0 ? 'block' : 'none'};">`;

                    pageItems.forEach((item, itemIndex) => {
                        const globalIndex = start + itemIndex;
                        const accordionId = `accordion-${vulnIndex}-${globalIndex}`;

                        // Severity badge
                        let severityColor, severityText;
                        if (item.score >= 9.0) {
                            severityColor = '#dc2626';
                            severityText = 'CRITICAL';
                        } else if (item.score >= 7.0) {
                            severityColor = '#ef4444';
                            severityText = 'HIGH';
                        } else if (item.score >= 4.0) {
                            severityColor = '#f59e0b';
                            severityText = 'MEDIUM';
                        } else {
                            severityColor = '#3b82f6';
                            severityText = 'LOW';
                        }

                        html += `
                            <div style="background: #111827; border: 1px solid #374151; border-radius: 8px; margin-bottom: 12px; overflow: hidden;">
                                <div style="padding: 15px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: background 0.3s ease;" 
                                     onclick="toggleAccordion('${accordionId}')"
                                     onmouseover="this.style.background='rgba(0,242,255,0.05)'"
                                     onmouseout="this.style.background='transparent'">
                                    <div style="flex: 1;">
                                        <strong style="color: #00f2ff; font-size: 15px;">${item.id}</strong>
                                        <div style="margin-top: 5px;">
                                            <span class="badge" style="background: ${severityColor}; color: #fff; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-right: 8px;">${severityText}</span>
                                            <span class="badge" style="background: #374151; color: #f3f4f6; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;">CVSS: ${item.score}</span>
                                            ${item.is_exploit ? '<span class="badge" style="background: #dc2626; color: #fff; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 8px;">💥 EXPLOIT AVAILABLE</span>' : ''}
                                        </div>
                                    </div>
                                    <div>
                                        <button style="background: #00f2ff; color: #000; border: none; padding: 8px 16px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;">
                                            DETAILS ▼
                                        </button>
                                    </div>
                                </div>
                                <div id="${accordionId}" style="display: none; padding: 20px; background: #0a0a0a; border-top: 1px solid #374151;">
                                    <div style="margin-bottom: 15px;">
                                        <div style="color: #9ca3af; font-size: 12px; text-transform: uppercase; margin-bottom: 8px;">Vulnerability Details</div>
                                        <div style="color: #f3f4f6; line-height: 1.6; font-size: 14px;">
                                            This vulnerability has been identified and cataloged. Review the official CVE database for comprehensive information.
                                        </div>
                                    </div>
                                    <div style="display: flex; gap: 10px;">
                                        <a href="${item.link}" target="_blank" style="background: linear-gradient(135deg, #00f2ff 0%, #0891b2 100%); color: #000; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 13px; display: inline-block;">
                                            🔗 View CVE Entry
                                        </a>
                                        ${item.is_exploit ? '<span style="background: #ef4444; color: #fff; padding: 10px 20px; border-radius: 6px; font-weight: 600; font-size: 13px;">⚠ Active Exploits Exist</span>' : ''}
                                    </div>
                                </div>
                            </div>
                        `;
                    });

                    html += `</div>`;
                }

                // Pagination controls
                if (totalPages > 1) {
                    html += `
                        <div style="display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 20px; padding-top: 15px; border-top: 1px solid #374151;">
                            <button onclick="changePage('${containerId}', -1)" style="background: #374151; color: #f3f4f6; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px;">
                                ← Previous
                            </button>
                            <span id="${containerId}-pageInfo" style="color: #9ca3af; font-size: 13px; min-width: 120px; text-align: center;">
                                Page 1 of ${totalPages}
                            </span>
                            <button onclick="changePage('${containerId}', 1)" style="background: #374151; color: #f3f4f6; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px;">
                                Next →
                            </button>
                        </div>
                    `;
                }

                html += `</div></div>`;

            } else {
                // Non-parsed vulnerability output
                html += `
                    <div style="background: #1f2937; border: 1px solid #f59e0b; border-radius: 8px; padding: 20px; margin-bottom: 15px;">
                        <h5 style="color: #f59e0b; margin: 0 0 15px 0; font-size: 15px;">
                            ⚠ Port ${vuln.port} - ${vuln.script}
                        </h5>
                        <pre style="background: #0a0a0a; color: #10b981; padding: 15px; border-radius: 6px; overflow: auto; font-family: 'Roboto Mono', monospace; font-size: 12px; line-height: 1.5; margin: 0;">${vuln.raw_output}</pre>
                    </div>
                `;
            }
        });

        html += '</div>';
        return html;
    }
});

// Global functions for accordion and pagination
function toggleAccordion(id) {
    const element = document.getElementById(id);
    if (element.style.display === 'none') {
        element.style.display = 'block';
    } else {
        element.style.display = 'none';
    }
}

function changePage(containerId, direction) {
    const container = document.getElementById(containerId);
    const pages = container.querySelectorAll('.vuln-page');
    let currentPage = 0;

    // Find current page
    pages.forEach((page, index) => {
        if (page.style.display === 'block') {
            currentPage = index;
        }
    });

    // Calculate new page
    let newPage = currentPage + direction;
    if (newPage < 0) newPage = 0;
    if (newPage >= pages.length) newPage = pages.length - 1;

    // Update display
    pages.forEach((page, index) => {
        page.style.display = index === newPage ? 'block' : 'none';
    });

    // Update page info
    const pageInfo = document.getElementById(`${containerId}-pageInfo`);
    if (pageInfo) {
        pageInfo.textContent = `Page ${newPage + 1} of ${pages.length}`;
    }
}