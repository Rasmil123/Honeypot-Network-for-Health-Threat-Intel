/** 
 * Healthcare Honeypot Dashboard Manager
 * Handles real-time log updates and statistics fetching.
 */

async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        document.getElementById('total_threats').textContent = data.total;
        document.getElementById('unique_ips').textContent = data.unique;
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

async function fetchLogs() {
    try {
        const response = await fetch('/api/logs');
        const logs = await response.json();
        
        const logBody = document.getElementById('log_body');
        // Clear previous logs
        logBody.innerHTML = '';
        
        // Populate with latest logs (assuming logs are in chronological order)
        // Reverse to show latest on top
        logs.reverse().forEach(log => {
            const row = document.createElement('tr');
            row.className = 'fade-in';
            
            row.innerHTML = `
                <td style="color: var(--text-muted); font-size: 0.8rem;">${log.timestamp}</td>
                <td class="ip-cell">${log.ip}</td>
                <td style="font-size: 0.8rem; opacity: 0.8;">${log.ua}</td>
                <td><span class="status-blocked">DENIED</span></td>
            `;
            
            logBody.appendChild(row);
        });
    } catch (error) {
        console.error('Error fetching logs:', error);
    }
}

// Initial fetch
fetchStats();
fetchLogs();

// Set up intervals for real-time feel
setInterval(fetchStats, 2000);
setInterval(fetchLogs, 2000);
