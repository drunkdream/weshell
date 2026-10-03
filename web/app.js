// weshell 前端逻辑。
//
// 安全约束：靶机回显属于不可信内容，一律通过 textContent 写入 DOM，
// 绝不使用 innerHTML 拼接，避免回显里的 HTML 被浏览器解析执行。
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);

  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  };

  // ---------- 请求封装 ----------

  // UNAUTHORIZED 用于提示调用方是否需要补令牌。
  const UNAUTHORIZED = 401;

  async function api(path, options = {}) {
    // 客户端兜底超时：服务端最多等 timeoutSeconds 秒，这里再宽限几秒。
    // 没有这个兜底，一旦请求不返回，界面会永远停在「执行中」。
    // 注意不能直接把 options 展开到 fetch 上：options.signal 若存在会覆盖掉
    // 超时用的 ctrl.signal，导致超时失效。所以外部的取消信号改为挂到同一个
    // controller 上，由它统一触发中止。
    const { signal: external, timeoutMs: customTimeout, ...rest } = options;
    const timeoutMs = customTimeout || state.timeoutMs;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    if (external) {
      if (external.aborted) {
        ctrl.abort();
      } else {
        external.addEventListener('abort', () => ctrl.abort(), { once: true });
      }
    }

    let resp;
    try {
      resp = await fetch('/api/' + path, {
        credentials: 'same-origin',
        signal: ctrl.signal,
        ...rest,
      });
    } catch (err) {
      clearTimeout(timer);
      if (err && err.name === 'AbortError') {
        const e = new Error('请求超时（' + Math.round(timeoutMs / 1000) + ' 秒未返回）');
        e.timedOut = true;
        throw e;
      }
      throw err;
    }
    clearTimeout(timer);
    let payload = null;
    try {
      payload = await resp.json();
    } catch (_) {
      const err = new Error('服务端返回了非 JSON 响应（HTTP ' + resp.status + '）');
      err.status = resp.status;
      throw err;
    }
    if (!resp.ok) {
      const err = new Error((payload && payload.error) || '请求失败（HTTP ' + resp.status + '）');
      err.status = resp.status;
      throw err;
    }
    return payload;
  }

  function post(path, body, signal) {
    return api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    });
  }

  function put(path, body) {
    return api(path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  function del(path) {
    return api(path, { method: 'DELETE' });
  }

  const state = {
    targets: [],
    types: [],
    current: null,
    editingID: null,
    cmds: [],
    cmdIndex: 0,
    running: false,
    // 客户端请求超时上限，启动时按服务端 -timeout 校准
    timeoutMs: 20000,
    // 当前进行中的请求，用于「取消」
    abort: null,
    // 文件管理当前所在目录
    fsPath: '.',
    // 系统监控自动刷新定时器
    sysTimer: null,
    // 进程管理：自动刷新定时器 / 当前视图 / 最近一次原始数据
    procTimer: null,
    procView: 'tree',
    procRaw: [],
    // 当前勾选的进程 PID 集合（用于「结束进程」批量操作）
    procSel: new Set(),
  };

  // ---------- 列表渲染 ----------

  function renderTargets() {
    const list = $('targetList');
    list.textContent = '';
    $('targetCount').textContent = String(state.targets.length);

    if (state.targets.length === 0) {
      list.appendChild(el('li', 'target-item', '暂无靶标'));
      return;
    }
    state.targets.forEach((t) => {
      const active = state.current && state.current.id === t.id ? ' active' : '';
      const li = el('li', 'target-item' + active);

      // 上半行：文字区占满剩余宽度，测试按钮固定在右侧
      const main = el('div', 'target-main');
      const text = el('div', 'target-text');
      text.appendChild(el('span', 'tname', t.name));
      text.appendChild(el('span', 'turl', t.url));

      const btn = el('button', 'btn-test', '测试');
      btn.title = '执行一次探针命令，验证该靶机是否可连通、命令能否正常回显';
      // 阻止冒泡，避免点测试时把列表项也选中了
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        testTarget(t, btn);
      });

      main.append(text, btn);
      li.appendChild(main);
      li.addEventListener('click', () => selectTarget(t.id));
      list.appendChild(li);
    });
  }

  // PROBE_COMMAND 是连通性探针：命令简短、无副作用、输出固定，
  // 便于判断"靶机可达 + 命令可执行 + 回显能取到"这一整条链路是否正常。
  const PROBE_COMMAND = 'echo weshell-ok';
  const PROBE_EXPECT = 'weshell-ok';

  // testTarget 执行一次探针命令，把结果与具体原因显示在列表项下方。
  async function testTarget(target, btn) {
    if (btn.dataset.busy === '1') return;
    btn.dataset.busy = '1';
    btn.textContent = '测试中';
    btn.className = 'btn-test testing';

    const li = btn.closest('.target-item');
    clearTestResult(li);

    let ok = false;
    let detail = '';
    try {
      const res = await post('targets/' + encodeURIComponent(target.id) + '/exec', { command: PROBE_COMMAND });
      const output = (res && res.output) || '';
      if (output.includes(PROBE_EXPECT)) {
        ok = true;
        detail = '靶机正常响应（' + res.latencyMs + 'ms）';
      } else {
        detail = explainFailure(res, output, null);
      }
    } catch (err) {
      detail = explainFailure(null, '', err);
    }

    btn.textContent = ok ? '正常' : '失败';
    btn.className = 'btn-test ' + (ok ? 'ok' : 'err');
    btn.title = detail;
    btn.dataset.busy = '0';
    showTestResult(li, ok, detail);

    // 失败时按钮状态保留更久，方便对照下面的原因文字
    setTimeout(() => {
      btn.textContent = '测试';
      btn.className = 'btn-test';
    }, ok ? 3000 : 10000);
  }

  // explainFailure 把失败信息翻译成可读且可操作的中文提示。
  // 原始错误（连接被拒、超时等）往往是一长串英文，直接抛给用户没法定位问题。
  function explainFailure(res, output, err) {
    const raw = (err && err.message) || (res && res.error) || '';

    if (raw) {
      if (/connection refused/i.test(raw)) {
        return '连接被拒绝：靶机未启动，或 URL 里的端口不对';
      }
      if (/no such host|could not resolve|lookup .* on /i.test(raw)) {
        return '主机名无法解析：检查 URL 中的域名/IP';
      }
      if (/timed out|timeout|deadline exceeded/i.test(raw)) {
        return '请求超时：靶机响应过慢，或网络不通';
      }
      if (/certificate|x509|tls/i.test(raw)) {
        return 'HTTPS 证书校验失败：靶机使用了自签名证书';
      }
      const httpMatch = raw.match(/HTTP (\d{3})/);
      if (httpMatch) {
        return '靶机返回 HTTP ' + httpMatch[1] + '：URL 路径不对，或该页面需要认证';
      }
      return raw;
    }

    if (res && res.status >= 400) {
      return '靶机返回 HTTP ' + res.status + '：URL 路径不对，或该页面需要认证';
    }
    if (!output) {
      return '靶机无回显：命令可能没执行成功。常见原因是参数名填错，或 passthru/system 被禁用';
    }
    return '未收到预期回显，靶机实际返回：' + output.slice(0, 200);
  }

  function clearTestResult(li) {
    if (!li) return;
    const old = li.querySelector('.test-result');
    if (old) old.remove();
  }

  // showTestResult 把结果直接显示在列表项下方。
  // 不能只放 title 属性——手机浏览器没有 hover，tooltip 根本看不到。
  function showTestResult(li, ok, detail) {
    if (!li) return;
    clearTestResult(li);
    const box = el('div', 'test-result ' + (ok ? 'ok' : 'err'), (ok ? '✓ ' : '✗ ') + detail);
    li.appendChild(box);
    setTimeout(() => box.remove(), ok ? 5000 : 20000);
  }

  function selectTarget(id) {
    const target = state.targets.find((t) => t.id === id);
    if (!target) return;
    state.current = target;
    renderTargets();

    $('empty').classList.add('hidden');
    $('workspace').classList.remove('hidden');
    $('tName').textContent = target.name;
    const type = state.types.find((x) => x.id === target.shellType);
    $('tMeta').textContent = [
      target.method,
      type ? type.label : target.shellType,
      '参数 ' + target.param,
      target.url,
    ].join(' · ');
    $('output').textContent = '';
    showTab('sys');
    state.fsPath = '.';
    $('fsPath').value = '.';
    $('fsList').textContent = '';
    $('fsEditor').classList.add('hidden');
    stopSysAuto();
    $('sysBody').textContent = '';
    $('sysUpdated').textContent = '';
    stopProcAuto();
    $('procBody').textContent = '';
    $('procUpdated').textContent = '';
    $('procSearch').value = '';
    state.procSel.clear();
    $('procAll').checked = false;
    $('cmdInput').focus();
  }

  function resetWorkspace() {
    state.current = null;
    renderTargets();
    $('workspace').classList.add('hidden');
    $('empty').classList.remove('hidden');
  }

  // ---------- 命令执行 ----------

  // 复位执行状态。放在 finally 里调用，保证无论成功、失败、超时都不会把界面锁死。
  function resetRunState() {
    state.running = false;
    state.abort = null;
    stopElapsed();
    const btn = $('btnRun');
    btn.disabled = false;
    btn.textContent = '执行';
  }

  // 执行中显示已等待秒数，让用户知道还在跑而不是卡死了
  let elapsedTimer = null;
  function startElapsed() {
    const btn = $('btnRun');
    const t0 = Date.now();
    stopElapsed();
    elapsedTimer = setInterval(() => {
      btn.textContent = '执行中 ' + Math.floor((Date.now() - t0) / 1000) + 's';
    }, 1000);
  }
  function stopElapsed() {
    if (elapsedTimer) {
      clearInterval(elapsedTimer);
      elapsedTimer = null;
    }
  }

  async function runCommand() {
    // 执行中再点按钮 = 取消当前请求
    if (state.running) {
      if (state.abort) state.abort.abort();
      return;
    }

    const input = $('cmdInput');
    const command = input.value.trim();
    if (!command) return;
    if (!state.current) {
      toast('请先选择一个靶标');
      return;
    }

    pushHistory(command);
    input.value = '';

    const btn = $('btnRun');
    state.running = true;
    state.abort = new AbortController();
    btn.disabled = false; // 保持可点击，允许用户取消
    startElapsed();

    let res = null;
    let errorMsg = null;
    try {
      res = await post('targets/' + encodeURIComponent(state.current.id) + '/exec', { command }, state.abort.signal);
    } catch (err) {
      errorMsg = err && err.name === 'AbortError' ? '已取消' : (err && err.message) || String(err);
    } finally {
      resetRunState();
    }

    renderResult(command, res, errorMsg);
    input.focus();
  }

  function renderResult(command, res, errorMsg) {
    const box = el('div', 'block');

    const head = el('div', 'block-head');
    head.appendChild(el('span', 'cmd', '$ ' + command));
    if (errorMsg) {
      head.appendChild(el('span', 'stat err', '失败 · ' + errorMsg));
    } else {
      const parts = ['HTTP ' + res.status, res.latencyMs + ' ms'];
      if (res.truncated) parts.push('回显已截断');
      const ok = res.ok && !res.error;
      head.appendChild(el('span', 'stat ' + (ok ? 'ok' : 'err'), parts.join(' · ')));
    }
    box.appendChild(head);

    if (!errorMsg) {
      const body = el('pre', 'body-text');
      if (res.output) {
        body.textContent = res.output;
      } else {
        body.classList.add('placeholder');
        body.textContent = res.error || '（靶机无回显）';
      }
      box.appendChild(body);
      box.appendChild(el('div', 'req', '请求 ' + res.requestUrl + '\n载荷 ' + res.payload));
    }

    $('output').appendChild(box);
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function toast(msg) {
    const row = el('div', 'history-row');
    row.appendChild(el('span', 'htime', '提示'));
    row.appendChild(el('span', 'hstatus err', ''));
    row.appendChild(el('span', 'hcmd', msg));
    $('output').appendChild(row);
  }

  function pushHistory(command) {
    if (state.cmds[state.cmds.length - 1] !== command) {
      state.cmds.push(command);
    }
    state.cmdIndex = state.cmds.length;
  }

  function recallHistory(step) {
    if (!state.cmds.length) return;
    state.cmdIndex = Math.max(0, Math.min(state.cmds.length, state.cmdIndex + step));
    $('cmdInput').value = state.cmds[state.cmdIndex] || '';
  }

  // ---------- 表单 ----------

  function updateTypeNote() {
    const type = state.types.find((t) => t.id === $('shellType').value);
    if (!type) return;
    const param = $('targetForm').elements.param.value.trim() || 'pass';
    $('typeNote').textContent = type.note + '\n靶机侧样本：' + type.snippet.replace('{param}', param);
  }

  function openForm(target) {
    state.editingID = target ? target.id : null;
    $('formTitle').textContent = target ? '编辑靶标' : '新建靶标';
    const form = $('targetForm');
    form.reset();
    const f = form.elements;
    if (target) {
      f.name.value = target.name || '';
      f.url.value = target.url || '';
      f.shellType.value = target.shellType || (state.types[0] && state.types[0].id) || '';
      f.param.value = target.param || 'pass';
      f.method.value = target.method || 'POST';
      f.note.value = target.note || '';
    } else {
      f.shellType.value = (state.types[0] && state.types[0].id) || '';
      f.param.value = 'pass';
      f.method.value = 'POST';
    }
    updateTypeNote();
    $('modalTarget').classList.remove('hidden');
    f.name.focus();
  }

  function closeModals() {
    $('modalTarget').classList.add('hidden');
    $('modalHistory').classList.add('hidden');
  }

  function formBody() {
    const f = $('targetForm').elements;
    return {
      name: f.name.value.trim(),
      url: f.url.value.trim(),
      shellType: f.shellType.value,
      param: f.param.value.trim(),
      method: f.method.value,
      note: f.note.value.trim(),
    };
  }

  async function submitForm(ev) {
    ev.preventDefault();
    const body = formBody();
    try {
      if (state.editingID) {
        await put('targets/' + encodeURIComponent(state.editingID), body);
      } else {
        await post('targets', body);
      }
      closeModals();
      const editingID = state.editingID;
      await loadTargets();
      if (editingID) selectTarget(editingID);
    } catch (err) {
      if (err.status === UNAUTHORIZED) requireToken();
      toast('保存失败：' + err.message);
    }
  }

  async function deleteTarget() {
    const target = state.current;
    if (!target) return;
    if (!confirm('确认删除靶标「' + target.name + '」？此操作不可恢复。')) return;
    try {
      await del('targets/' + encodeURIComponent(target.id));
      await loadTargets();
      resetWorkspace();
    } catch (err) {
      if (err.status === UNAUTHORIZED) requireToken();
      toast('删除失败：' + err.message);
    }
  }

  async function loadHistory() {
    try {
      const records = await api('history?limit=100');
      const box = $('historyBody');
      box.textContent = '';
      if (!records.length) {
        box.appendChild(el('p', 'note', '暂无执行记录。'));
      } else {
        records.slice().reverse().forEach((r) => {
          const row = el('div', 'history-row');
          row.appendChild(el('span', 'htime', String(r.time || '').replace('T', ' ').slice(0, 19)));
          row.appendChild(el('span', 'hstatus ' + (r.ok ? 'ok' : 'err'), r.ok ? '成功' : '失败'));
          row.appendChild(el('span', 'hcmd', r.command));
          box.appendChild(row);
        });
      }
      $('modalHistory').classList.remove('hidden');
    } catch (err) {
      if (err.status === UNAUTHORIZED) requireToken();
      toast('读取执行记录失败：' + err.message);
    }
  }

  function requireToken() {
    toast('需要提供访问令牌（-auth 指定的值）才能调用接口');
  }

  // ---------- 数据加载 ----------

  async function loadTypes() {
    state.types = await api('types');
    const select = $('shellType');
    select.textContent = '';
    state.types.forEach((t) => {
      const opt = el('option', null, t.label);
      opt.value = t.id;
      select.appendChild(opt);
    });
    updateTypeNote();
  }

  async function loadTargets() {
    state.targets = await api('targets');
    renderTargets();
  }

  // 常驻显示启动参数 -lab 指定的本机靶机地址，仅在配置了该参数时显示。
  async function loadConfig() {
    const cfg = await api('config');

    // 服务端超时 + 5 秒宽限，避免前端比服务端先放弃
    if (cfg && cfg.timeoutSeconds > 0) {
      state.timeoutMs = (cfg.timeoutSeconds + 5) * 1000;
    }

    const box = $('labUrl');
    const url = cfg && cfg.labUrl;
    if (!url) {
      box.hidden = true;
      return;
    }
    box.textContent = '本机靶机 ' + url;
    box.title = url;
    box.hidden = false;
  }

  // ---------- 文件管理 ----------

  // 在终端 / 文件两个标签页间切换；切到文件时若尚未加载则拉取当前目录。
  function showTab(name) {
    const term = name === 'term';
    $('termPanel').classList.toggle('hidden', !term);
    $('fsPanel').classList.toggle('hidden', term || name !== 'fs');
    $('sysPanel').classList.toggle('hidden', name !== 'sys');
    $('procPanel').classList.toggle('hidden', name !== 'proc');
    document.querySelectorAll('.tab').forEach((b) => {
      b.classList.toggle('active', b.dataset.tab === name);
    });
    if (name === 'fs' && state.current && !$('fsList').childElementCount) {
      loadFs(state.fsPath);
    }
    if (name === 'sys' && state.current) {
      loadSys();
    }
    if (name === 'proc' && state.current) {
      loadProc();
    }
  }

  // 读取靶机系统资源概览：GET /api/targets/{id}/sys/info
  async function loadSys() {
    if (!state.current) return;
    const body = $('sysBody');
    if (!body.childElementCount) body.appendChild(el('div', 'fs-hint', '加载中…'));
    try {
      const d = await api('targets/' + encodeURIComponent(state.current.id) + '/sys/info');
      renderSys(d, body);
      $('sysUpdated').textContent = '更新于 ' + new Date().toLocaleTimeString();
    } catch (err) {
      body.textContent = '';
      body.appendChild(el('div', 'fs-err', '加载失败：' + err.message));
    }
  }

  function fmtBytes(b) {
    b = Number(b) || 0;
    if (b <= 0) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, n = b;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n.toFixed(0) : n.toFixed(n >= 10 ? 0 : 1)) + ' ' + u[i];
  }

  function fmtDuration(sec) {
    sec = Math.floor(sec);
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600),
      m = Math.floor((sec % 3600) / 60), s = sec % 60;
    const parts = [];
    if (d) parts.push(d + '天');
    if (h) parts.push(h + '时');
    if (m) parts.push(m + '分');
    parts.push(s + '秒');
    return parts.join('');
  }

  function pct(v) {
    const n = Number(v);
    if (!isFinite(n)) return 0;
    return Math.max(0, Math.min(100, n * 100));
  }

  function sysCard(title, val) {
    const c = el('div', 'sys-card');
    c.appendChild(el('div', 'sys-card-title', title));
    c.appendChild(el('div', 'sys-card-val', String(val)));
    return c;
  }

  function progressRow(label, percent) {
    const row = el('div', 'sys-card-row');
    row.appendChild(el('span', 'sys-k', label));
    const bar = el('div', 'sys-bar');
    const fill = el('div', 'sys-bar-fill');
    fill.style.width = pct(percent / 100) + '%';
    bar.appendChild(fill);
    const wrap = el('div', 'sys-bar-wrap');
    wrap.appendChild(bar);
    wrap.appendChild(el('span', 'sys-bar-pct', pct(percent / 100).toFixed(0) + '%'));
    row.appendChild(wrap);
    return row;
  }

  function renderSys(d, body) {
    body.textContent = '';
    const over = el('div', 'sys-cards');
    over.appendChild(sysCard('主机', d.hostname || '—'));
    over.appendChild(sysCard('系统', d.os || '—'));
    const up = (d.uptime || '').toString().split(/\s+/)[0];
    over.appendChild(sysCard('运行时长', up ? fmtDuration(parseFloat(up)) : '—'));
    const la = Array.isArray(d.loadavg) ? d.loadavg : [];
    over.appendChild(sysCard('负载 (1/5/15)', la.join(' / ') || '—'));
    body.appendChild(over);

    const cpu = d.cpu || {};
    const cpuCard = el('div', 'sys-card wide');
    cpuCard.appendChild(el('div', 'sys-card-title', 'CPU'));
    const cr = el('div', 'sys-card-row');
    cr.appendChild(el('span', 'sys-k', '核心数'));
    cr.appendChild(el('span', 'sys-v', String(cpu.cores || '—')));
    cpuCard.appendChild(cr);
    if (cpu.model) {
      const mr = el('div', 'sys-card-row');
      mr.appendChild(el('span', 'sys-k', '型号'));
      mr.appendChild(el('span', 'sys-v', cpu.model));
      cpuCard.appendChild(mr);
    }
    cpuCard.appendChild(progressRow('使用率', pct(cpu.usage)));
    body.appendChild(cpuCard);

    const mem = d.mem || {};
    const total = Number(mem.MemTotal) || 0;
    const avail = Number(mem.MemAvailable) || Number(mem.MemFree) || 0;
    const used = total - avail;
    const memCard = el('div', 'sys-card wide');
    memCard.appendChild(el('div', 'sys-card-title', '内存'));
    const mrow = el('div', 'sys-card-row');
    mrow.appendChild(el('span', 'sys-k', '已用 / 总量'));
    mrow.appendChild(el('span', 'sys-v', fmtBytes(used) + ' / ' + fmtBytes(total)));
    memCard.appendChild(mrow);
    memCard.appendChild(progressRow('占用', total > 0 ? (used / total) * 100 : 0));
    body.appendChild(memCard);

    const disks = Array.isArray(d.disks) ? d.disks : [];
    // 过滤掉 tmpfs / proc / sysfs 等虚拟文件系统，仅聚焦真实磁盘（根挂载点始终保留）
    const skipFs = new Set(['tmpfs', 'devtmpfs', 'proc', 'sysfs', 'cgroup', 'cgroup2', 'mqueue', 'debugfs', 'tracefs', 'securityfs', 'pstore', 'bpf', 'configfs', 'fusectl', 'hugetlbfs', 'autofs', 'binfmt_misc', 'rpc_pipefs', 'nsfs']);
    const show = disks.filter((dk) => dk.mount === '/' || !skipFs.has(dk.fs));
    const diskCard = el('div', 'sys-card wide');
    diskCard.appendChild(el('div', 'sys-card-title', '硬盘（共 ' + show.length + ' 个挂载点）'));
    if (!show.length) {
      diskCard.appendChild(el('div', 'fs-hint', '（无数据，靶机可能禁用了 shell_exec / df）'));
    } else {
      show.forEach((dk) => {
        const r = el('div', 'sys-card-row');
        const mp = dk.mount + (dk.fs ? '  (' + dk.fs + ')' : '');
        r.appendChild(el('span', 'sys-k', mp));
        r.appendChild(el('span', 'sys-v', fmtBytes(Number(dk.used)) + ' / ' + fmtBytes(Number(dk.total))));
        diskCard.appendChild(r);
        diskCard.appendChild(progressRow('使用率', Number(dk.use) || 0));
      });
    }
    body.appendChild(diskCard);

  }

  // ---------- 进程管理（独立页） ----------

  // 读取靶机进程列表：GET /api/targets/{id}/proc/list
  async function loadProc() {
    if (!state.current) return;
    const body = $('procBody');
    if (!body.childElementCount) body.appendChild(el('div', 'fs-hint', '加载中…'));
    try {
      const d = await api('targets/' + encodeURIComponent(state.current.id) + '/proc/list');
      state.procRaw = Array.isArray(d.procs) ? d.procs : [];
      renderProc();
      $('procUpdated').textContent = '更新于 ' + new Date().toLocaleTimeString();
    } catch (err) {
      body.textContent = '';
      body.appendChild(el('div', 'fs-err', '加载失败：' + err.message));
    }
  }

  function stopProcAuto() {
    if (state.procTimer) { clearInterval(state.procTimer); state.procTimer = null; }
    const cb = $('procAuto');
    if (cb) cb.checked = false;
  }

  // 按当前视图（树形 / 列表）与搜索词渲染进程。
  function renderProc() {
    const body = $('procBody');
    body.textContent = '';
    const procs = state.procRaw || [];
    const q = ($('procSearch').value || '').trim().toLowerCase();
    if (!procs.length) {
      body.appendChild(el('div', 'fs-hint', '（无数据，靶机可能禁用了 shell_exec / ps）'));
      return;
    }
    if (state.procView === 'tree') renderProcTree(procs, q, body);
    else renderProcList(procs, q, body);
  }

  // 由 (pid, ppid) 构建森林：父进程不存在于列表中的即根；子进程按 PID 排序。
  function buildForest(procs) {
    const byPid = new Map();
    procs.forEach((p) => byPid.set(String(p.pid), p));
    procs.forEach((p) => { p._children = []; });
    const roots = [];
    procs.forEach((p) => {
      const parent = byPid.get(String(p.ppid));
      if (parent && parent !== p) parent._children.push(p);
      else roots.push(p);
    });
    const sortRec = (n) => { n._children.sort((a, b) => Number(a.pid) - Number(b.pid)); n._children.forEach(sortRec); };
    roots.sort((a, b) => Number(a.pid) - Number(b.pid));
    roots.forEach(sortRec);
    return roots;
  }

  function renderProcTree(procs, q, body) {
    const forest = buildForest(procs);
    const selfMatch = (p) => !q ? false :
      (String(p.pid).toLowerCase().includes(q) ||
       String(p.user).toLowerCase().includes(q) ||
       String(p.cmd).toLowerCase().includes(q));
    const mark = (node) => {
      node._self = selfMatch(node);
      let any = node._self;
      node._children.forEach((c) => { if (mark(c)) any = true; });
      node._any = any;
      return any;
    };
    forest.forEach(mark);

    const tree = el('ul', 'proc-tree');
    const renderNode = (node) => {
      if (q && !node._any) return null;
      const li = el('li', 'proc-node');
      const row = el('div', 'proc-row');
      const pid = String(node.pid);
      const cb = el('input', 'proc-cb');
      cb.type = 'checkbox';
      cb.value = pid;
      cb.checked = state.procSel.has(pid);
      cb.addEventListener('click', (ev) => ev.stopPropagation());
      cb.addEventListener('change', () => {
        if (cb.checked) state.procSel.add(pid); else state.procSel.delete(pid);
        row.classList.toggle('proc-sel', cb.checked);
        updateProcKillBtn();
      });
      if (cb.checked) row.classList.add('proc-sel');
      row.appendChild(cb);
      const hasKids = node._children.length > 0;
      const toggle = el('span', 'proc-toggle' + (hasKids ? '' : ' leaf'));
      if (hasKids) {
        toggle.textContent = '▾';
        toggle.addEventListener('click', (ev) => {
          ev.stopPropagation();
          const collapsed = li.classList.toggle('collapsed');
          toggle.textContent = collapsed ? '▸' : '▾';
        });
      } else {
        toggle.textContent = '•';
      }
      row.appendChild(toggle);
      row.appendChild(el('span', 'mono proc-pid', String(node.pid)));
      row.appendChild(el('span', 'mono proc-user', node.user));
      row.appendChild(el('span', 'mono proc-cpu', (Number(node.cpu) || 0).toFixed(1) + '%'));
      row.appendChild(el('span', 'proc-cmd', node.cmd));
      if (node._self) row.classList.add('proc-hit');
      li.appendChild(row);
      if (hasKids) {
        const ul = el('ul', 'proc-children');
        node._children.forEach((c) => {
          const child = renderNode(c);
          if (child) ul.appendChild(child);
        });
        li.appendChild(ul);
      }
      return li;
    };
    forest.forEach((n) => {
      const li = renderNode(n);
      if (li) tree.appendChild(li);
    });
    body.appendChild(tree);
  }

  function renderProcList(procs, q, body) {
    let list = procs;
    if (q) {
      list = procs.filter((p) =>
        String(p.pid).toLowerCase().includes(q) ||
        String(p.user).toLowerCase().includes(q) ||
        String(p.cmd).toLowerCase().includes(q));
    }
    const sorted = list.slice().sort((a, b) => (Number(b.cpu) || 0) - (Number(a.cpu) || 0));
    const tbl = el('table', 'sys-proc');
    const thead = el('tr', '');
    ['', 'PID', 'PPID', '用户', 'CPU%', '内存%', '命令'].forEach((h) => thead.appendChild(el('th', h === '' ? 'proc-cb-cell' : '', h)));
    tbl.appendChild(thead);
    sorted.forEach((p) => {
      const tr = el('tr', '');
      const pid = String(p.pid);
      const cb = el('input', 'proc-cb');
      cb.type = 'checkbox';
      cb.value = pid;
      cb.checked = state.procSel.has(pid);
      cb.addEventListener('change', () => {
        if (cb.checked) state.procSel.add(pid); else state.procSel.delete(pid);
        tr.classList.toggle('proc-sel', cb.checked);
        updateProcKillBtn();
      });
      if (cb.checked) tr.classList.add('proc-sel');
      const cbTd = el('td', 'proc-cb-cell');
      cbTd.appendChild(cb);
      tr.appendChild(cbTd);
      tr.appendChild(el('td', 'mono', String(p.pid)));
      tr.appendChild(el('td', 'mono', String(p.ppid)));
      tr.appendChild(el('td', 'mono', String(p.user)));
      tr.appendChild(el('td', 'mono', (Number(p.cpu) || 0).toFixed(1)));
      tr.appendChild(el('td', 'mono', (Number(p.mem) || 0).toFixed(1)));
      tr.appendChild(el('td', 'mono', String(p.cmd)));
      tbl.appendChild(tr);
    });
    const wrap = el('div', 'sys-proc-wrap');
    wrap.appendChild(tbl);
    body.appendChild(wrap);
  }

  // 更新「结束进程」按钮文字，显示当前勾选数量。
  function updateProcKillBtn() {
    const b = $('procKill');
    if (!b) return;
    const n = state.procSel.size;
    b.textContent = n ? '结束进程 (' + n + ')' : '结束进程';
  }

  // 结束当前勾选的进程（可批量）：POST /api/targets/{id}/proc/kill
  async function killProc() {
    if (!state.current) return;
    const ids = Array.from(state.procSel);
    if (!ids.length) { toast('请先勾选要结束的进程'); return; }
    const sig = $('procForce').checked ? 9 : 15;
    const label = sig === 9 ? 'SIGKILL' : 'SIGTERM';
    if (!confirm('确认向选中的 ' + ids.length + ' 个进程发送 ' + label + ' 信号？')) return;
    let okCount = 0, failCount = 0;
    await Promise.all(ids.map(async (pid) => {
      try {
        const r = await post('targets/' + encodeURIComponent(state.current.id) + '/proc/kill', { pid, signal: sig });
        if (r && r.ok) okCount++; else failCount++;
      } catch (e) {
        failCount++;
      }
    }));
    toast('已发送 ' + label + '：成功 ' + okCount + '，失败 ' + failCount);
    state.procSel.clear();
    $('procAll').checked = false;
    loadProc();
  }

  function stopSysAuto() {
    if (state.sysTimer) { clearInterval(state.sysTimer); state.sysTimer = null; }
    const cb = $('sysAuto');
    if (cb) cb.checked = false;
  }

  // UTF-8 字符串 <-> base64（靶机以 base64 回传文件内容，避免二进制/特殊字符破坏回显截取）。
  function b64encodeUtf8(str) {
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    bytes.forEach((b) => (bin += String.fromCharCode(b)));
    return btoa(bin);
  }
  function b64decodeUtf8(b64) {
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  function fileToB64(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => {
        const bytes = new Uint8Array(fr.result);
        let bin = '';
        bytes.forEach((b) => (bin += String.fromCharCode(b)));
        resolve(btoa(bin));
      };
      fr.onerror = reject;
      fr.readAsArrayBuffer(file);
    });
  }
  function downloadB64(name, b64) {
    const bin = atob(b64);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const blob = new Blob([bytes]);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // 从输入框跳转到目录：相对路径基于当前目录解析为绝对路径再请求
  function navigateFs(raw) {
    let dir = (raw || '').trim();
    if (!dir) {
      loadFs(state.fsPath);
      return;
    }
    if (dir !== '/' && !dir.startsWith('/')) {
      const base = state.fsPath === '.' ? '' : state.fsPath.replace(/\/+$/, '');
      dir = base ? base + '/' + dir : dir;
    }
    loadFs(dir);
  }

  // 列出目录：GET /api/targets/{id}/fs/list?path=
  async function loadFs(dir) {
    if (!state.current) return;
    state.fsPath = dir;
    $('fsPath').value = dir;
    const list = $('fsList');
    list.textContent = '';
    list.appendChild(el('li', 'fs-row fs-hint', '加载中…'));
    try {
      const data = await api('targets/' + encodeURIComponent(state.current.id) + '/fs/list?path=' + encodeURIComponent(dir));
      const cur = data.path || dir;
      state.fsPath = cur;
      $('fsPath').value = cur;
      list.textContent = '';
      if (!data.entries.length) {
        list.appendChild(el('li', 'fs-row fs-hint', '（空目录）'));
      }
      data.entries.forEach((e) => {
        const li = el('li', 'fs-row' + (e.isDir ? ' is-dir' : ''));
        li.appendChild(el('span', 'fs-name', e.name + (e.isDir ? '/' : '')));
        li.appendChild(el('span', 'fs-meta', e.isDir ? '目录' : (e.size + ' B · ' + e.mode)));
        li.addEventListener('click', () => {
          if (e.isDir) loadFs(e.path);
          else openFsFile(e.path, e.name);
        });
        const acts = el('span', 'fs-acts');
        if (!e.isDir) {
          const ed = el('button', 'btn ghost xs', '编辑');
          ed.addEventListener('click', (ev) => { ev.stopPropagation(); openFsFile(e.path, e.name); });
          acts.appendChild(ed);
          const dl = el('button', 'btn ghost xs', '下载');
          dl.addEventListener('click', (ev) => { ev.stopPropagation(); downloadFs(e.path, e.name); });
          acts.appendChild(dl);
        }
        const del = el('button', 'btn danger xs', '删');
        del.addEventListener('click', (ev) => { ev.stopPropagation(); deleteFs(e.path); });
        acts.appendChild(del);
        li.appendChild(acts);
        list.appendChild(li);
      });
    } catch (err) {
      list.textContent = '';
      list.appendChild(el('li', 'fs-row fs-err', '加载失败：' + err.message));
    }
  }

  // 根据编辑器内容重算左侧行号，并同步滚动位置（与 textarea 逐行对齐）。
  function syncFsGutter() {
    const ta = $('fsContent');
    const gut = $('fsGutter');
    const n = ta.value.split('\n').length;
    let s = '';
    for (let i = 1; i <= n; i++) s += i + '\n';
    gut.textContent = s;
    gut.scrollTop = ta.scrollTop;
  }

  // 读取文件到编辑器：GET /api/targets/{id}/fs/read?path=
  async function openFsFile(path, name) {
    try {
      const f = await api('targets/' + encodeURIComponent(state.current.id) + '/fs/read?path=' + encodeURIComponent(path));
      $('fsEditName').textContent = name + '  (' + f.size + ' B)';
      $('fsContent').value = b64decodeUtf8(f.base64);
      $('fsEditor').dataset.path = path;
      $('fsEditor').classList.remove('hidden');
      syncFsGutter();
    } catch (err) {
      toast('读取失败：' + err.message);
    }
  }

  // 保存编辑器内容：POST /api/targets/{id}/fs/write
  async function saveFsFile() {
    const path = $('fsEditor').dataset.path;
    if (!path) return;
    try {
      await post('targets/' + encodeURIComponent(state.current.id) + '/fs/write', {
        path,
        base64: b64encodeUtf8($('fsContent').value),
      });
      toast('已保存 ' + path);
      $('fsEditor').classList.add('hidden');
      loadFs(state.fsPath);
    } catch (err) {
      toast('保存失败：' + err.message);
    }
  }

  async function deleteFs(path) {
    if (!confirm('确认删除 ' + path + '？')) return;
    try {
      await post('targets/' + encodeURIComponent(state.current.id) + '/fs/delete', { path });
      toast('已删除 ' + path);
      loadFs(state.fsPath);
    } catch (err) {
      toast('删除失败：' + err.message);
    }
  }

  async function downloadFs(path, name) {
    try {
      const f = await api('targets/' + encodeURIComponent(state.current.id) + '/fs/download?path=' + encodeURIComponent(path));
      downloadB64(name, f.base64);
    } catch (err) {
      toast('下载失败：' + err.message);
    }
  }

  async function uploadFs(file) {
    if (!file) return;
    const dir = state.fsPath === '.' ? '.' : state.fsPath.replace(/\/$/, '');
    const path = dir === '.' ? file.name : dir + '/' + file.name;
    try {
      const b64 = await fileToB64(file);
      await post('targets/' + encodeURIComponent(state.current.id) + '/fs/upload', { path, base64: b64 });
      toast('已上传 ' + path);
      loadFs(state.fsPath);
    } catch (err) {
      toast('上传失败：' + err.message);
    }
  }

  function newFsFile() {
    const name = prompt('新文件名（将创建于当前目录 ' + state.fsPath + '）：');
    if (!name) return;
    const dir = state.fsPath === '.' ? '.' : state.fsPath.replace(/\/$/, '');
    const path = dir === '.' ? name : dir + '/' + name;
    $('fsEditName').textContent = name + '  (新建)';
    $('fsContent').value = '';
    $('fsEditor').dataset.path = path;
    $('fsEditor').classList.remove('hidden');
    syncFsGutter();
  }

  // ---------- 事件绑定 ----------

  function bind() {
    $('btnNew').addEventListener('click', () => openForm(null));
    $('btnEdit').addEventListener('click', () => {
      if (state.current) openForm(state.current);
    });
    $('btnDelete').addEventListener('click', deleteTarget);
    $('btnHistory').addEventListener('click', loadHistory);

    $('targetForm').addEventListener('submit', submitForm);
    $('shellType').addEventListener('change', updateTypeNote);
    $('targetForm').elements.param.addEventListener('input', updateTypeNote);

    document.querySelectorAll('[data-close]').forEach((btn) => {
      btn.addEventListener('click', closeModals);
    });
    document.querySelectorAll('.modal').forEach((modal) => {
      modal.addEventListener('click', (ev) => {
        if (ev.target === modal) closeModals();
      });
    });
    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') closeModals();
    });

    $('btnRun').addEventListener('click', runCommand);
    $('cmdInput').addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        runCommand();
      } else if (ev.key === 'ArrowUp') {
        ev.preventDefault();
        recallHistory(-1);
      } else if (ev.key === 'ArrowDown') {
        ev.preventDefault();
        recallHistory(1);
      }
    });

    document.querySelectorAll('.chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        $('cmdInput').value = chip.dataset.cmd;
        $('cmdInput').focus();
      });
    });

    // 文件管理相关事件
    document.querySelectorAll('.tab').forEach((b) => {
      b.addEventListener('click', () => showTab(b.dataset.tab));
    });
    $('sysRefresh').addEventListener('click', loadSys);
    $('sysAuto').addEventListener('change', (ev) => {
      stopSysAuto();
      if (ev.target.checked) {
        loadSys();
        state.sysTimer = setInterval(loadSys, 3000);
      }
    });
    $('procRefresh').addEventListener('click', loadProc);
    $('procAuto').addEventListener('change', (ev) => {
      stopProcAuto();
      if (ev.target.checked) {
        loadProc();
        state.procTimer = setInterval(loadProc, 3000);
      }
    });
    document.querySelectorAll('[data-pview]').forEach((b) => {
      b.addEventListener('click', () => {
        state.procView = b.dataset.pview;
        document.querySelectorAll('[data-pview]').forEach((x) => x.classList.toggle('active', x === b));
        renderProc();
      });
    });
    $('procSearch').addEventListener('input', () => {
      if (state.current) renderProc();
      $('procAll').checked = false;
    });
    $('procAll').addEventListener('change', (ev) => {
      const on = ev.target.checked;
      document.querySelectorAll('.proc-cb').forEach((cb) => {
        cb.checked = on;
        if (on) state.procSel.add(cb.value); else state.procSel.delete(cb.value);
      });
      renderProc();
      updateProcKillBtn();
    });
    $('procKill').addEventListener('click', killProc);
    updateProcKillBtn();
    $('fsUp').addEventListener('click', () => {
      const p = state.fsPath;
      if (!p || p === '/') return;
      const clean = p.replace(/\/+$/, '');
      const i = clean.lastIndexOf('/');
      const up = i <= 0 ? (i === 0 ? '/' : '.') : clean.slice(0, i);
      loadFs(up);
    });
    $('fsPath').addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        navigateFs($('fsPath').value);
      }
    });
    $('fsNew').addEventListener('click', newFsFile);
    $('fsUpload').addEventListener('click', () => $('fsFileInput').click());
    $('fsFileInput').addEventListener('change', (ev) => {
      uploadFs(ev.target.files[0]);
      ev.target.value = '';
    });
    $('fsSave').addEventListener('click', saveFsFile);
    $('fsEditClose').addEventListener('click', () => $('fsEditor').classList.add('hidden'));
    $('fsContent').addEventListener('input', syncFsGutter);
    $('fsContent').addEventListener('scroll', () => {
      $('fsGutter').scrollTop = $('fsContent').scrollTop;
    });
  }

  // ---------- 启动 ----------

  bind();
  (async () => {
    try {
      await loadConfig();
      await loadTypes();
      await loadTargets();
    } catch (err) {
      toast('初始化失败：' + err.message);
    }
  })();
})();
