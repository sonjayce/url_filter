import { ProcessURLs, LoadBlacklist, LoadWhitelist, SetBlacklist, SetWhitelist, ParseURLFile, ParseExcelFile, ExportTxt, ExportXlsx } from '../wailsjs/go/main/App';

// ===== DOM Elements =====
const inputArea = document.getElementById('inputArea');
const resultArea = document.getElementById('resultArea');
const logArea = document.getElementById('logArea');
const statusEl = document.getElementById('status');
const inputCount = document.getElementById('inputCount');

const btnStart = document.getElementById('btnStart');
const btnPause = document.getElementById('btnPause');
const btnExportTxt = document.getElementById('btnExportTxt');
const btnExportXlsx = document.getElementById('btnExportXlsx');
const btnImport = document.getElementById('btnImport');
const btnClearInput = document.getElementById('btnClearInput');
const btnClearLog = document.getElementById('btnClearLog');
const btnLoadBlack = document.getElementById('btnLoadBlack');
const btnLoadWhite = document.getElementById('btnLoadWhite');

const chkGov = document.getElementById('chkGov');
const chkBlack = document.getElementById('chkBlack');
const chkWhite = document.getElementById('chkWhite');
const chkDedup = document.getElementById('chkDedup');
const chkProto = document.getElementById('chkProto');
const chkKeyword = document.getElementById('chkKeyword');
const chkStatus = document.getElementById('chkStatus');
const chkFilterLog = document.getElementById('chkFilterLog');

const entryKeyword = document.getElementById('entryKeyword');
const entryCodes = document.getElementById('entryCodes');
const entryTimeout = document.getElementById('entryTimeout');
const entryThreads = document.getElementById('entryThreads');

// ===== State =====
let isProcessing = false;
let isPaused = false;
let blacklistDomains = [];
let whitelistDomains = [];
let allLogLines = [];

// ===== Event Listeners =====

// Input count
inputArea.addEventListener('input', () => {
    const lines = inputArea.value.split('\n').filter(l => l.trim()).length;
    inputCount.textContent = `${lines} 个域名`;
});

// Keyword toggle
chkKeyword.addEventListener('change', () => {
    entryKeyword.disabled = !chkKeyword.checked;
    if (!chkKeyword.checked) entryKeyword.value = '';
});

// Status toggle
chkStatus.addEventListener('change', () => {
    const enabled = chkStatus.checked;
    entryCodes.disabled = !enabled;
    entryTimeout.disabled = !enabled;
    entryThreads.disabled = !enabled;
});

// Start processing
btnStart.addEventListener('click', async () => {
    if (isProcessing) return;

    const input = inputArea.value.trim();
    if (!input) {
        statusEl.textContent = '请先粘贴域名列表';
        return;
    }

    isProcessing = true;
    btnStart.disabled = true;
    btnStart.textContent = '处理中...';
    statusEl.textContent = '正在处理中...';

    // Clear previous results
    resultArea.value = '';
    logArea.value = '';

    // Build options
    const opts = {
        EnableGov: chkGov.checked,
        EnableBlack: chkBlack.checked,
        EnableWhite: chkWhite.checked,
        EnableDedup: chkDedup.checked,
        RemoveProto: chkProto.checked,
        EnableKeyword: chkKeyword.checked,
        Keyword: entryKeyword.value,
        EnableStatus: chkStatus.checked,
        AllowedCodes: parseCodes(entryCodes.value),
        Timeout: parseInt(entryTimeout.value) || 5,
        Threads: parseInt(entryThreads.value) || 20,
        BlackDomains: {},
        WhiteDomains: {},
    };

    try {
        const result = await ProcessURLs(input, opts);
        resultArea.value = result.Results.join('\n');
        updateStats(result.Counters);

        // Store and display logs with reasons
        allLogLines = result.Logs || [];
        applyLogFilter();

        statusEl.textContent = `完成！保留 ${result.Results.length} 条`;
    } catch (err) {
        console.error(err);
        statusEl.textContent = `错误: ${err.message}`;
    } finally {
        isProcessing = false;
        btnStart.disabled = false;
        btnStart.textContent = '开始处理';
    }
});

// Pause/Resume
btnPause.addEventListener('click', () => {
    isPaused = !isPaused;
    btnPause.textContent = isPaused ? '继续' : '暂停';
    statusEl.textContent = isPaused ? '已暂停' : '正在处理中...';
    log(isPaused ? '暂停' : '继续', isPaused ? '用户暂停了任务' : '用户恢复了任务');
});

btnExportTxt.addEventListener('click', async () => {
    const content = resultArea.value.trim();
    if (!content) {
        alert('没有可导出的结果');
        return;
    }

    try {
        const handle = await window.showSaveFilePicker({
            suggestedName: 'filtered_results.txt',
            types: [{ description: '文本文件', accept: { 'text/plain': ['.txt'] } }]
        });
        const writable = await handle.createWritable();
        await writable.write(content);
        await writable.close();
        const count = content.split('\n').filter(l => l.trim()).length;
        log('导出', `TXT 导出 ${count} 条`);
    } catch (err) {
        if (err.name !== 'AbortError') {
            console.error(err);
            alert('导出失败: ' + err.message);
        }
    }
});

btnExportXlsx.addEventListener('click', async () => {
    const content = resultArea.value.trim();
    if (!content) {
        alert('没有可导出的结果');
        return;
    }

    try {
        const handle = await window.showSaveFilePicker({
            suggestedName: 'filtered_results.xlsx',
            types: [{ description: 'Excel 文件', accept: { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'] } }]
        });
        const writable = await handle.createWritable();

        const base64 = await ExportXlsx(content);
        const binaryStr = atob(base64);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        await writable.write(bytes);
        await writable.close();

        const count = content.split('\n').filter(l => l.trim()).length;
        log('导出', `XLSX 导出 ${count} 条`);
    } catch (err) {
        if (err.name !== 'AbortError') {
            console.error(err);
            alert('导出失败: ' + err.message);
        }
    }
});

// Import file
btnImport.addEventListener('click', () => {
    document.getElementById('fileImport').click();
});

document.getElementById('fileImport').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const fileName = file.name.toLowerCase();
    const isExcel = fileName.endsWith('.xlsx') || fileName.endsWith('.xls');
    const isCsv = fileName.endsWith('.csv');

    let hosts = [];

    if (isExcel) {
        // 读取 Excel 文件为 base64
        const arrayBuffer = await file.arrayBuffer();
        const bytes = new Uint8Array(arrayBuffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64Data = btoa(binary);
        hosts = await ParseExcelFile(base64Data);
        log('导入', `Excel 导入 ${hosts.length} 条`);
    } else {
        // TXT / CSV 文件
        const content = await file.text();
        if (isCsv) {
            // CSV 特殊处理：跳过第一行表头，按逗号分割
            const lines = content.split('\n').slice(1);
            const csvContent = lines.join('\n');
            hosts = await ParseURLFile(csvContent);
        } else {
            hosts = await ParseURLFile(content);
        }
        log('导入', `文件导入 ${hosts.length} 条`);
    }

    // 追加到现有输入
    const existing = inputArea.value.trim();
    if (existing) {
        inputArea.value = existing + '\n' + hosts.join('\n');
    } else {
        inputArea.value = hosts.join('\n');
    }

    const total = inputArea.value.split('\n').filter(l => l.trim()).length;
    inputCount.textContent = `${total} 个域名`;
    statusEl.textContent = `已导入 ${hosts.length} 条`;

    e.target.value = '';
});

// Clear input
btnClearInput.addEventListener('click', () => {
    inputArea.value = '';
    inputCount.textContent = '0 个域名';
    statusEl.textContent = '已清空输入区';
});

// Log filter toggle
chkFilterLog.addEventListener('change', () => {
    applyLogFilter();
});

function applyLogFilter() {
    const onlyFiltered = chkFilterLog.checked;
    logArea.value = '';

    if (!allLogLines || allLogLines.length === 0) return;

    allLogLines.forEach(line => {
        if (onlyFiltered) {
            // 仅显示 过滤/无效/重复 的条目
            if (line.startsWith('[过滤]') || line.startsWith('[无效]') || line.startsWith('[重复]')) {
                logArea.value += line + '\n';
            }
        } else {
            logArea.value += line + '\n';
        }
    });
    logArea.scrollTop = logArea.scrollHeight;
}

// Clear log
btnClearLog.addEventListener('click', () => {
    logArea.value = '';
    allLogLines = [];
});

// Load blacklist
btnLoadBlack.addEventListener('click', () => {
    document.getElementById('fileBlack').click();
});

document.getElementById('fileBlack').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const content = await file.text();
    blacklistDomains = content.split('\n')
        .map(l => l.trim().toLowerCase())
        .filter(l => l.length > 0);
    await SetBlacklist(blacklistDomains);
    log('黑名单', `加载完成: ${blacklistDomains.length} 条`);

    e.target.value = '';
});

// Load whitelist
btnLoadWhite.addEventListener('click', () => {
    document.getElementById('fileWhite').click();
});

document.getElementById('fileWhite').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const content = await file.text();
    whitelistDomains = content.split('\n')
        .map(l => l.trim().toLowerCase())
        .filter(l => l.length > 0);
    await SetWhitelist(whitelistDomains);
    log('白名单', `加载完成: ${whitelistDomains.length} 条`);

    e.target.value = '';
});

// ===== Helper Functions =====

function parseCodes(codesStr) {
    const codes = {};
    if (!codesStr) return codes;
    codesStr.split(',').forEach(s => {
        const n = parseInt(s.trim());
        if (!isNaN(n)) codes[n] = true;
    });
    return codes;
}

function updateStats(counters) {
    document.getElementById('statTotal').textContent = counters.Total || 0;
    document.getElementById('statKeep').textContent = counters.Keep || 0;
    document.getElementById('statGov').textContent = counters.Gov || 0;
    document.getElementById('statBlack').textContent = counters.Black || 0;
    document.getElementById('statWhite').textContent = counters.White || 0;
    document.getElementById('statKeyword').textContent = counters.KeyBlock || 0;
    document.getElementById('statStatus').textContent = counters.StatusBlock || 0;
    document.getElementById('statDup').textContent = counters.Dup || 0;
    document.getElementById('statInvalid').textContent = counters.Invalid || 0;
}

function domainListToMap(domains) {
    const map = {};
    domains.forEach(d => {
        map[d] = true;
    });
    return map;
}

function log(type, message) {
    const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    logArea.value += `[${time}] [${type}] ${message}\n`;
    logArea.scrollTop = logArea.scrollHeight;
}
