/**
 * activity-logger.js
 * Logs all user activity to activity.json file — no database needed.
 * Place in: C:\Users\pravakar\Desktop\Nodejs\pdfnew\activity-logger.js
 */

const fs   = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, 'activity.json');

function readLog() {
    try {
        if (!fs.existsSync(LOG_FILE)) return [];
        return JSON.parse(fs.readFileSync(LOG_FILE, 'utf8'));
    } catch { return []; }
}

function writeLog(entries) {
    fs.writeFileSync(LOG_FILE, JSON.stringify(entries, null, 2));
}

function logActivity(entry) {
    const entries = readLog();
    entries.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        ...entry
    });
    // Keep last 10000 entries
    if (entries.length > 10000) entries.splice(10000);
    writeLog(entries);
}

module.exports = {
    logLogin:    (email, ip) => logActivity({ type: 'login',    email, ip }),
    logLogout:   (email, ip) => logActivity({ type: 'logout',   email, ip }),
    logToolUse:  (email, tool, filename, filesize) => logActivity({ type: 'tool_use',  email, tool, filename, filesize }),
    logDownload: (email, tool, filename) => logActivity({ type: 'download', email, tool, filename }),
    getAll:      () => readLog(),
    getFiltered: (filter) => readLog().filter(e => {
        if (filter.email && e.email !== filter.email) return false;
        if (filter.type  && e.type  !== filter.type)  return false;
        if (filter.tool  && e.tool  !== filter.tool)  return false;
        return true;
    }),
};