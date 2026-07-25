import { StartProcessing, GetProcessingState, GetProcessingResult, LoadConfig, SaveConfig, PauseProcessing, ResumeProcessing, CancelProcessing, ExtractAssets, LoadBlacklist, LoadWhitelist, SetBlacklist, SetWhitelist, ParseURLFile, ParseCSVFile, ParseExcelFile, ExportTxt, ExportXlsx } from '../wailsjs/go/main/App';

// ===== DOM Elements =====
const inputArea = document.getElementById('inputArea');
const resultArea = document.getElementById('resultArea');
const logArea = document.getElementById('logArea');
const statusEl = document.getElementById('status');
const inputCount = document.getElementById('inputCount');
const filterPage = document.getElementById('filterPage');
const assetPage = document.getElementById('assetPage');
const btnPageFilter = document.getElementById('btnPageFilter');
const btnPageAssets = document.getElementById('btnPageAssets');
const filterHeaderActions = document.getElementById('filterHeaderActions');
const assetInput = document.getElementById('assetInput');
const chkFilterPrivate = document.getElementById('chkFilterPrivate');
const btnExtractAssets = document.getElementById('btnExtractAssets');
const btnClearAssets = document.getElementById('btnClearAssets');

const btnStart = document.getElementById('btnStart');
const btnPause = document.getElementById('btnPause');
const btnCancel = document.getElementById('btnCancel');
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
let isCancelRequested = false;
let blacklistDomains = [];
let whitelistDomains = [];
let allLogLines = [];
let configSaveTimer = null;

function switchPage(page) {
    const isAssets = page === 'assets';
    filterPage.classList.toggle('hidden', isAssets);
    assetPage.classList.toggle('hidden', !isAssets);
    btnPageFilter.classList.toggle('active', !isAssets);
    btnPageAssets.classList.toggle('active', isAssets);
    filterHeaderActions.classList.toggle('hidden', isAssets);
}

btnPageFilter.addEventListener('click', () => switchPage('filter'));
btnPageAssets.addEventListener('click', () => switchPage('assets'));

btnExtractAssets.addEventListener('click', async () => {
    const input = assetInput.value.trim();
    if (!input) {
        statusEl.textContent = '请先粘贴待处理的资产文本';
        return;
    }
    btnExtractAssets.disabled = true;
    statusEl.textContent = '正在提取资产...';
    try {
        const result = await ExtractAssets(input, chkFilterPrivate.checked);
        renderAssetResults(result);
        statusEl.textContent = `提取完成：${result.URLs.length + result.RootDomains.length + result.Subdomains.length + result.IPs.length} 项资产`;
    } catch (err) {
        console.error(err);
        statusEl.textContent = `资产提取失败: ${err.message}`;
    } finally {
        btnExtractAssets.disabled = false;
    }
});

btnClearAssets.addEventListener('click', () => {
    assetInput.value = '';
    renderAssetResults({ URLs: [], RootDomains: [], Subdomains: [], IPs: [], CNetworks: [] });
    statusEl.textContent = '已清空资产输入';
});

document.querySelectorAll('.asset-copy').forEach(button => {
    button.addEventListener('click', async () => {
        const target = document.getElementById(button.dataset.target);
        const content = target.value.trim();
        if (!content) {
            statusEl.textContent = '当前分类没有可复制内容';
            return;
        }
        try {
            await navigator.clipboard.writeText(content);
            statusEl.textContent = '已复制当前分类结果';
        } catch (err) {
            target.focus();
            target.select();
            document.execCommand('copy');
            statusEl.textContent = '已复制当前分类结果';
        }
    });
});

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
    scheduleConfigSave();
});

// Status toggle
chkStatus.addEventListener('change', () => {
    const enabled = chkStatus.checked;
    entryCodes.disabled = !enabled;
    entryTimeout.disabled = !enabled;
    entryThreads.disabled = !enabled;
    scheduleConfigSave();
});

[chkGov, chkBlack, chkWhite, chkDedup, chkProto].forEach(element => {
    element.addEventListener('change', scheduleConfigSave);
});
[entryKeyword, entryCodes, entryTimeout, entryThreads].forEach(element => {
    element.addEventListener('input', scheduleConfigSave);
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
    isPaused = false;
    isCancelRequested = false;
    btnStart.disabled = true;
    btnStart.textContent = '处理中...';
    statusEl.textContent = '正在处理中...';
    updateProcessingControls();

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
        await persistConfig();
        await StartProcessing(input, opts);
        const result = await waitForProcessingResult();
        resultArea.value = result.Results.join('\n');
        updateStats(result.Counters);

        // Store and display logs with reasons
        allLogLines = result.Logs || [];
        applyLogFilter();

        statusEl.textContent = result.Canceled
            ? `已取消，保留 ${result.Results.length} 条`
            : `完成！保留 ${result.Results.length} 条`;
    } catch (err) {
        console.error(err);
        statusEl.textContent = `错误: ${err.message}`;
    } finally {
        isProcessing = false;
        isPaused = false;
        isCancelRequested = false;
        btnStart.disabled = false;
        btnStart.textContent = '开始处理';
        updateProcessingControls();
    }
});

btnPause.addEventListener('click', async () => {
    if (!isProcessing || isCancelRequested) return;
    try {
        const changed = isPaused ? await ResumeProcessing() : await PauseProcessing();
        if (!changed) return;
        isPaused = !isPaused;
        btnPause.textContent = isPaused ? '继续' : '暂停';
        statusEl.textContent = isPaused ? '已暂停' : '正在处理中...';
        updateProcessingControls();
    } catch (err) {
        console.error(err);
        statusEl.textContent = `控制任务失败: ${err.message}`;
    }
});

btnCancel.addEventListener('click', async () => {
    if (!isProcessing || isCancelRequested) return;
    isCancelRequested = true;
    btnCancel.disabled = true;
    btnPause.disabled = true;
    statusEl.textContent = '正在取消...';
    try {
        await CancelProcessing();
    } catch (err) {
        console.error(err);
        statusEl.textContent = `取消失败: ${err.message}`;
        isCancelRequested = false;
        updateProcessingControls();
    }
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
    const isExcel = fileName.endsWith('.xlsx');
    const isLegacyExcel = fileName.endsWith('.xls');
    const isCsv = fileName.endsWith('.csv');

    let hosts = [];

    try {
        if (isLegacyExcel) {
            throw new Error('暂不支持 .xls 文件，请另存为 .xlsx 后再导入');
        }

        if (isExcel) {
            // 读取 XLSX 文件为 base64
            const arrayBuffer = await file.arrayBuffer();
            const bytes = new Uint8Array(arrayBuffer);
            let binary = '';
            for (let i = 0; i < bytes.length; i += 0x8000) {
                binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
            }
            hosts = await ParseExcelFile(btoa(binary));
            log('导入', `XLSX 导入 ${hosts.length} 条`);
        } else {
            const content = await file.text();
            if (isCsv) {
                hosts = await ParseCSVFile(content);
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
    } catch (err) {
        console.error(err);
        statusEl.textContent = `导入失败: ${err.message}`;
        alert(`导入失败: ${err.message}`);
    } finally {
        e.target.value = '';
    }
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
    scheduleConfigSave();

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
    scheduleConfigSave();

    e.target.value = '';
});

// ===== Helper Functions =====

function renderAssetResults(result) {
    const groups = [
        ['assetUrls', 'assetCountUrls', result?.URLs || []],
        ['assetDomains', 'assetCountDomains', result?.RootDomains || []],
        ['assetSubdomains', 'assetCountSubdomains', result?.Subdomains || []],
        ['assetIps', 'assetCountIps', result?.IPs || []],
        ['assetCnets', 'assetCountCnets', result?.CNetworks || []],
    ];
    groups.forEach(([textId, countId, values]) => {
        document.getElementById(textId).value = values.join('\n');
        document.getElementById(countId).textContent = values.length;
    });
}

function currentConfig() {
    return {
        EnableGov: chkGov.checked,
        EnableBlack: chkBlack.checked,
        EnableWhite: chkWhite.checked,
        EnableDedup: chkDedup.checked,
        EnableKeyword: chkKeyword.checked,
        RemoveProto: chkProto.checked,
        EnableStatus: chkStatus.checked,
        Keyword: entryKeyword.value,
        AllowedCodes: parseCodes(entryCodes.value),
        Timeout: parseInt(entryTimeout.value) || 5,
        Threads: parseInt(entryThreads.value) || 20,
        BlackDomains: blacklistDomains,
        WhiteDomains: whitelistDomains,
    };
}

function applyConfig(config) {
    chkGov.checked = !!config.EnableGov;
    chkBlack.checked = !!config.EnableBlack;
    chkWhite.checked = !!config.EnableWhite;
    chkDedup.checked = !!config.EnableDedup;
    chkProto.checked = !!config.RemoveProto;
    chkKeyword.checked = !!config.EnableKeyword;
    chkStatus.checked = !!config.EnableStatus;
    entryKeyword.value = config.Keyword || '';
    entryCodes.value = Object.keys(config.AllowedCodes || {}).filter(code => config.AllowedCodes[code]).join(',');
    entryTimeout.value = config.Timeout || 5;
    entryThreads.value = config.Threads || 20;
    blacklistDomains = Array.isArray(config.BlackDomains) ? config.BlackDomains : [];
    whitelistDomains = Array.isArray(config.WhiteDomains) ? config.WhiteDomains : [];

    entryKeyword.disabled = !chkKeyword.checked;
    entryTimeout.disabled = !chkStatus.checked;
    entryThreads.disabled = !chkStatus.checked;
    entryCodes.disabled = !chkStatus.checked;
}

async function initializeConfig() {
    try {
        const config = await LoadConfig();
        applyConfig(config);
        await SetBlacklist(blacklistDomains);
        await SetWhitelist(whitelistDomains);
    } catch (err) {
        console.error(err);
        statusEl.textContent = `配置加载失败: ${err.message}`;
    }
}

async function persistConfig() {
    await SaveConfig(currentConfig());
}

function scheduleConfigSave() {
    if (configSaveTimer !== null) clearTimeout(configSaveTimer);
    configSaveTimer = setTimeout(() => {
        configSaveTimer = null;
        persistConfig().catch(err => console.error('配置保存失败', err));
    }, 300);
}

function updateProcessingControls() {
    btnPause.disabled = !isProcessing || isCancelRequested;
    btnCancel.disabled = !isProcessing || isCancelRequested;
    btnPause.textContent = isPaused ? '继续' : '暂停';
}

async function waitForProcessingResult() {
    while (true) {
        const state = await GetProcessingState();
        if (!state.Active) {
            throw new Error('处理任务不存在');
        }
        if (state.Finished) {
            return await GetProcessingResult();
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
}

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

updateProcessingControls();
initializeConfig();
