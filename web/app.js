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
    // 访问过的目录历史（最新在前，用于输入框下拉提示）
    fsHistory: [],
    // 文件编辑器是否开启自动换行（软换行时行号无法对齐，会隐藏行号栏）
    fsWrap: true,
    // 系统监控自动刷新定时器
    sysTimer: null,
    // 进程管理：自动刷新定时器 / 当前视图 / 最近一次原始数据
    procTimer: null,
    procView: 'tree',
    procRaw: [],
    // 当前勾选的进程 PID 集合（用于「结束进程」批量操作）
    procSel: new Set(),
    // 监听端口：自动刷新定时器 / 最近一次原始数据
    portsTimer: null,
    portsRaw: [],
    // PHP 环境能力研判：自动刷新定时器
    phpinfoTimer: null,
  };

  // ---------- 列表渲染 ----------

  // 操作系统图标（内联 SVG，跟随 currentColor）。
  const OS_ICON = {
    windows: '<svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor" aria-hidden="true"><path d="M3 5.6l8-1.1v7H3zM12.4 4.4L21 3v8.5h-8.6zM3 12.5h8v7l-8-1.1zM12.4 12.5H21V21l-8.6-1.4z"/></svg>',
    // Tux 企鹅：橘色脚/嘴 + 两侧鳍 + 浅色肚皮，避免被看成两个圆叠加的雪人
    linux: '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true">'
      + '<path d="M6.9 19.2c-1.7.7-2.8 1.8-3.2 2.5 1.5.5 2.9.2 3.9-.4.7-.4 1.2-1 1.5-1.6z" fill="#f2a33c"/>'
      + '<path d="M17.1 19.2c1.7.7 2.8 1.8 3.2 2.5-1.5.5-2.9.2-3.9-.4-.7-.4-1.2-1-1.5-1.6z" fill="#f2a33c"/>'
      + '<ellipse cx="6.4" cy="13.6" rx="1.6" ry="3.1" fill="currentColor"/>'
      + '<ellipse cx="17.6" cy="13.6" rx="1.6" ry="3.1" fill="currentColor"/>'
      + '<ellipse cx="12" cy="13.8" rx="5.7" ry="6.4" fill="currentColor"/>'
      + '<ellipse cx="12" cy="14.8" rx="3.9" ry="4.7" fill="var(--bg)"/>'
      + '<circle cx="12" cy="6.6" r="4.7" fill="currentColor"/>'
      + '<ellipse cx="12" cy="8" rx="3.3" ry="3" fill="var(--bg)"/>'
      + '<circle cx="10.4" cy="6.2" r="1.05" fill="currentColor"/>'
      + '<circle cx="13.6" cy="6.2" r="1.05" fill="currentColor"/>'
      + '<path d="M12 8.1l1.8 1.4-1.8 1.2-1.8-1.2z" fill="#f2a33c"/>'
      + '</svg>',
    unknown: '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
  };

  // 由引擎类型推断操作系统：ASP/ASP-VBS 依赖 IIS，必为 Windows；
  // PHP 型多数跑在 Linux，但也可能在 Windows 上，故标注为推断值。
  function osOfTarget(t) {
    if (t.shellType === 'asp' || t.shellType === 'asp-vbs') {
      return { key: 'windows', label: 'Windows（ASP/IIS，由引擎类型推断）' };
    }
    if (t.shellType === 'php-eval' || t.shellType === 'php-cmd') {
      return { key: 'linux', label: 'Linux（由 PHP 引擎推断，实际也可能是 Windows）' };
    }
    return { key: 'unknown', label: '未知操作系统' };
  }

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

      const badge = el('span', 'tbadge ' + (t.verified ? 'verified' : 'unverified'), t.verified ? '已验证' : '未验证');

      const btn = el('button', 'btn-test', '测试');
      btn.title = '执行一次探针命令，验证该靶机是否可连通、命令能否正常回显';
      // 阻止冒泡，避免点测试时把列表项也选中了
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        testTarget(t, btn);
      });

      const os = osOfTarget(t);
      const osIcon = el('span', 'tos-icon');
      osIcon.innerHTML = OS_ICON[os.key];
      osIcon.title = os.label;

      main.append(osIcon, text, badge, btn);
      li.appendChild(main);
      li.addEventListener('click', () => selectTarget(t.id));
      list.appendChild(li);
    });
  }

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
      const res = await post('targets/' + encodeURIComponent(target.id) + '/verify');
      if (res && res.verified) {
        ok = true;
        detail = '靶机正常响应（' + res.latencyMs + 'ms）';
      } else {
        detail = explainFailure(res, (res && res.output) || '', null);
      }
    } catch (err) {
      detail = explainFailure(null, '', err);
    }

    btn.textContent = ok ? '正常' : '失败';
    btn.className = 'btn-test ' + (ok ? 'ok' : 'err');
    btn.title = detail;
    btn.dataset.busy = '0';
    showTestResult(li, ok, detail);

    // 后端已在 /verify 中持久化验证状态，这里同步本列表项的徽章（不整列重渲染，保留按钮态）
    target.verified = ok;
    const badge = li.querySelector('.tbadge');
    if (badge) {
      badge.textContent = ok ? '已验证' : '未验证';
      badge.className = 'tbadge ' + (ok ? 'verified' : 'unverified');
    }

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
      target.proxy ? '代理 ' + target.proxy : null,
      target.url,
    ].filter(Boolean).join(' · ');
    $('output').textContent = '';
    showTab('info');
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
    stopPortsAuto();
    $('portsBody').textContent = '';
    $('portsUpdated').textContent = '';
    $('portsSearch').value = '';
    stopPhpInfoAuto();
    $('phpinfoBody').textContent = '';
    $('phpinfoUpdated').textContent = '';
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
    const actualErr = errorMsg || (res && res.error) || '';
    if (actualErr) {
      head.appendChild(el('span', 'stat err', '失败 · ' + actualErr));
    } else {
      const parts = ['HTTP ' + res.status, res.latencyMs + ' ms'];
      if (res.truncated) parts.push('回显已截断');
      const ok = res.ok && !res.error;
      head.appendChild(el('span', 'stat ' + (ok ? 'ok' : 'err'), parts.join(' · ')));
    }
    box.appendChild(head);

    const body = el('pre', 'body-text');
    if (res && res.output) {
      body.textContent = res.output;
    } else if (actualErr) {
      body.classList.add('placeholder');
      body.textContent = actualErr;
    } else {
      body.classList.add('placeholder');
      body.textContent = '（靶机无回显）';
    }
    box.appendChild(body);
    if (res) box.appendChild(el('div', 'req', '请求 ' + res.requestUrl + '\n载荷 ' + res.payload));

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
      f.proxy.value = target.proxy || '';
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
    $('modalSettings').classList.add('hidden');
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
      proxy: f.proxy.value.trim(),
    };
  }

  async function submitForm(ev) {
    ev.preventDefault();
    const form = ev.target;
    const btn = form.querySelector('button[type="submit"]');
    if (btn) { btn.disabled = true; btn.dataset.label = btn.textContent; btn.textContent = '保存中…'; }
    let body;
    try {
      body = formBody();
    } catch (err) {
      if (btn) { btn.disabled = false; btn.textContent = btn.dataset.label || '保存'; }
      toast('表单读取失败：' + err.message);
      return;
    }
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
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = btn.dataset.label || '保存'; }
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

  // 打开全局设置弹窗，并拉取当前 UA 设置回填。
  async function openSettings() {
    let ua = '';
    try {
      const s = await api('settings');
      if (s && typeof s.userAgent === 'string') ua = s.userAgent;
    } catch (e) { /* 用默认空值即可 */ }
    const mode = ua === '' ? 'default' : (ua === 'random' ? 'random' : 'specified');
    $('uaMode').value = mode;
    $('uaValue').value = mode === 'specified' ? (ua || navigator.userAgent) : '';
    $('uaValueWrap').hidden = mode !== 'specified';
    $('modalSettings').classList.remove('hidden');
    $('uaMode').focus();
  }

  // 保存全局设置：把 UI 选择映射回后端约定的 userAgent 取值。
  async function saveSettings() {
    const mode = $('uaMode').value;
    let ua = '';
    if (mode === 'random') ua = 'random';
    else if (mode === 'specified') ua = $('uaValue').value.trim();
    try {
      await put('settings', { userAgent: ua });
      $('modalSettings').classList.add('hidden');
    } catch (e) {
      alert('保存失败：' + (e && e.message ? e.message : e));
    }
  }

  // ---------- 文件管理 ----------

  // 在终端 / 文件两个标签页间切换；切到文件时若尚未加载则拉取当前目录。
  function showTab(name) {
    const term = name === 'term';
    $('termPanel').classList.toggle('hidden', !term);
    $('fsPanel').classList.toggle('hidden', term || name !== 'fs');
    $('sysPanel').classList.toggle('hidden', name !== 'sys');
    $('procPanel').classList.toggle('hidden', name !== 'proc');
    $('portsPanel').classList.toggle('hidden', name !== 'ports');
    $('phpinfoPanel').classList.toggle('hidden', name !== 'phpinfo');
    $('infoPanel').classList.toggle('hidden', name !== 'info');
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
    if (name === 'ports' && state.current) {
      loadPorts();
    }
    if (name === 'phpinfo' && state.current) {
      loadPhpInfo();
    }
    if (name === 'info' && state.current) {
      loadInfo();
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

  // 读取靶机请求/响应报文：GET /api/targets/{id}/headers
  async function loadInfo() {
    if (!state.current) return;
    const body = $('infoBody');
    if (!body.childElementCount) body.appendChild(el('div', 'fs-hint', '加载中…'));
    try {
      const d = await api('targets/' + encodeURIComponent(state.current.id) + '/headers');
      renderInfo(d, body);
      $('infoUpdated').textContent = '更新于 ' + new Date().toLocaleTimeString();
    } catch (err) {
      body.textContent = '';
      body.appendChild(el('div', 'fs-err', '加载失败：' + err.message));
    }
  }

  // 把请求头 / 响应头渲染为可复制的键值列表。
  function renderInfo(d, body) {
    body.textContent = '';
    if (!d.ok && !d.requestHeaders && !d.responseHeaders) {
      body.appendChild(el('div', 'fs-err', '请求失败：' + (d.error || '未知错误')));
      return;
    }

    const head = el('div', 'info-summary');
    head.appendChild(el('span', 'info-kv', 'URL: ' + (d.requestUrl || '—')));
    head.appendChild(el('span', 'info-kv', 'HTTP ' + (d.status || 0)));
    head.appendChild(el('span', 'info-kv', '耗时 ' + (d.latencyMs || 0) + ' ms'));
    if (d.error) head.appendChild(el('span', 'info-kv err', '错误: ' + d.error));
    body.appendChild(head);

    if (d.requestHeaders) {
      body.appendChild(headerTable('请求头（管理端发出）', d.requestHeaders));
    }
    if (d.responseHeaders) {
      body.appendChild(headerTable('响应头（靶机返回）', d.responseHeaders));
    }
  }

  // 把 http.Header 渲染成两列表格：键 + 多值（逗号拼接）。
  function headerTable(title, headers) {
    const block = el('div', 'info-block');
    block.appendChild(el('h4', 'info-title', title));
    const table = el('div', 'info-table');
    Object.keys(headers).sort().forEach((k) => {
      const row = el('div', 'info-row');
      row.appendChild(el('div', 'info-key', k));
      row.appendChild(el('div', 'info-val', (headers[k] || []).join(', ')));
      table.appendChild(row);
    });
    if (!Object.keys(headers).length) {
      table.appendChild(el('div', 'info-row', '（空）'));
    }
    block.appendChild(table);
    return block;
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

    // 网络地址：内网 IP（靶机网卡地址）与公网 IP（出网探测结果）
    const intIPs = Array.isArray(d.intIPs) ? d.intIPs : [];
    const pubIP = d.pubIP || '';
    const netCard = el('div', 'sys-card wide');
    netCard.appendChild(el('div', 'sys-card-title', '网络地址'));
    const irow = el('div', 'sys-card-row');
    irow.appendChild(el('span', 'sys-k', '内网 IP'));
    irow.appendChild(el('span', 'sys-v', intIPs.length ? intIPs.join(', ') : '—'));
    netCard.appendChild(irow);
    const prow = el('div', 'sys-card-row');
    prow.appendChild(el('span', 'sys-k', '公网 IP'));
    prow.appendChild(el('span', 'sys-v', pubIP ? pubIP : '—（靶机无出网或已禁用）'));
    netCard.appendChild(prow);
    body.appendChild(netCard);

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
      const cmdSpan = el('span', 'proc-cmd', node.cmd);
      cmdSpan.title = node.cmd;
      row.appendChild(cmdSpan);
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
      const cmdTd = el('td', 'mono proc-cmd-cell', String(p.cmd));
      cmdTd.title = String(p.cmd);
      tr.appendChild(cmdTd);
      tbl.appendChild(tr);
    });
    const wrap = el('div', 'proc-list-wrap');
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

  // ---------- 监听端口管理（独立页） ----------

  // 读取靶机监听端口：GET /api/targets/{id}/ports
  async function loadPorts() {
    if (!state.current) return;
    const body = $('portsBody');
    if (!body.childElementCount) body.appendChild(el('div', 'fs-hint', '加载中…'));
    try {
      const d = await api('targets/' + encodeURIComponent(state.current.id) + '/ports');
      state.portsRaw = Array.isArray(d.ports) ? d.ports : [];
      renderPorts();
      $('portsUpdated').textContent = '更新于 ' + new Date().toLocaleTimeString();
    } catch (err) {
      body.textContent = '';
      body.appendChild(el('div', 'fs-err', '加载失败：' + err.message));
    }
  }

  function stopPortsAuto() {
    if (state.portsTimer) { clearInterval(state.portsTimer); state.portsTimer = null; }
    const cb = $('portsAuto');
    if (cb) cb.checked = false;
  }

  // 按搜索词过滤并渲染端口表格。
  function renderPorts() {
    const body = $('portsBody');
    body.textContent = '';
    const ports = state.portsRaw || [];
    const q = ($('portsSearch').value || '').trim().toLowerCase();
    const list = q ? ports.filter((p) =>
      String(p.proto).toLowerCase().includes(q) ||
      String(p.addr).toLowerCase().includes(q) ||
      String(p.port).includes(q) ||
      String(p.comm).toLowerCase().includes(q) ||
      String(p.pid).includes(q)) : ports;
    if (!ports.length) {
      body.appendChild(el('div', 'fs-hint', '（无数据，靶机可能未开放任何监听端口，或禁用了 /proc 读取）'));
      return;
    }
    if (!list.length) {
      body.appendChild(el('div', 'fs-hint', '（无匹配项）'));
      return;
    }
    // 按地址族、端口号排序，端口号小的在前，便于对照
    const sorted = list.slice().sort((a, b) => (Number(a.port) || 0) - (Number(b.port) || 0));
    const tbl = el('table', 'sys-proc');
    const thead = el('tr', '');
    ['协议', '本地地址', '端口', '进程', 'PID', 'inode'].forEach((h) => thead.appendChild(el('th', '', h)));
    tbl.appendChild(thead);
    sorted.forEach((p) => {
      const tr = el('tr', '');
      tr.appendChild(el('td', 'mono', String(p.proto || '—')));
      tr.appendChild(el('td', 'mono', String(p.addr || '—')));
      tr.appendChild(el('td', 'mono', String(p.port || '—')));
      tr.appendChild(el('td', 'mono', String(p.comm || '—')));
      tr.appendChild(el('td', 'mono', String(p.pid || '—')));
      tr.appendChild(el('td', 'mono', String(p.inode || '—')));
      tbl.appendChild(tr);
    });
    const wrap = el('div', 'sys-proc-wrap');
    wrap.appendChild(tbl);
    body.appendChild(wrap);
  }

  // ---------- 端口扫描（在靶机上对目标主机发起 TCP 探测） ----------

  // ---- 端口/主机展开与分批（前端分批，保证每次请求 ≤30s）----
  const SCAN_PORT_BATCH = 5;   // 每请求携带的端口数；ASP/PHP 每端口最坏 2s → 5×2=10s ≤30s
  const SCAN_HOSTS_MAX = 512;   // 与后端 ExpandHosts 上限一致
  const SCAN_PORTS_MAX = 5000;  // 与后端 ExpandPorts 上限一致
  const SCAN_REQ_TIMEOUT = 60000; // 单批请求的护栏超时（实际靶机脚本 ≤24s，这里留足余量）

  function expandPorts(spec) {
    const out = [];
    for (let part of String(spec).split(',')) {
      part = part.trim();
      if (!part) continue;
      if (part.includes('-')) {
        const [a, b] = part.split('-').map((x) => parseInt(x, 10));
        if (!Number.isFinite(a) || !Number.isFinite(b) || a < 0 || b > 65535 || a > b) throw new Error('端口范围非法：' + part);
        if (b - a + 1 > 2000) throw new Error('单段端口范围不能超过 2000（' + part + '）');
        for (let p = a; p <= b; p++) out.push(p);
      } else {
        const p = parseInt(part, 10);
        if (!Number.isFinite(p) || p < 0 || p > 65535) throw new Error('端口非法：' + part);
        out.push(p);
      }
      if (out.length > SCAN_PORTS_MAX) throw new Error('端口总数不能超过 ' + SCAN_PORTS_MAX);
    }
    return out;
  }

  function ipToInt(ip) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
    if (!m) return null;
    const nums = [m[1], m[2], m[3], m[4]].map(Number);
    if (nums.some((n) => n > 255)) return null;
    return (((nums[0] * 256 + nums[1]) * 256 + nums[2]) * 256 + nums[3]) >>> 0;
  }
  function intToIp(n) {
    return [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255].join('.');
  }
  function expandHosts(spec) {
    const out = [];
    const seen = new Set();
    const add = (h) => { if (!seen.has(h)) { seen.add(h); out.push(h); } };
    for (let part of String(spec).split(',')) {
      part = part.trim();
      if (!part) continue;
      if (part.includes('/')) {
        const [base, bits] = part.split('/');
        const n = ipToInt(base);
        const b = parseInt(bits, 10);
        if (n === null || !Number.isFinite(b) || b < 0 || b > 32) throw new Error('CIDR 非法：' + part);
        const size = Math.pow(2, 32 - b);
        if (size > SCAN_HOSTS_MAX) throw new Error('CIDR 主机数超过 ' + SCAN_HOSTS_MAX + '（' + part + '）');
        const start = Math.floor(n / size) * size;
        for (let i = 0; i < size; i++) add(intToIp((start + i) >>> 0));
      } else if (part.includes('-')) {
        const [a, b] = part.split('-').map((x) => x.trim());
        const na = ipToInt(a), nb = ipToInt(b);
        if (na === null || nb === null) throw new Error('IP 区间非法：' + part);
        if (na > nb) throw new Error('IP 区间起点大于终点：' + part);
        if (nb - na + 1 > SCAN_HOSTS_MAX) throw new Error('IP 区间主机数超过 ' + SCAN_HOSTS_MAX);
        for (let i = na; i <= nb; i++) add(intToIp(i >>> 0));
      } else {
        if (ipToInt(part) === null && !/^[a-zA-Z0-9.-]+$/.test(part)) throw new Error('主机非法：' + part);
        add(part);
      }
      if (out.length > SCAN_HOSTS_MAX) throw new Error('主机总数不能超过 ' + SCAN_HOSTS_MAX);
    }
    return out;
  }

  function chunkArray(arr, n) {
    const out = [];
    for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
    return out;
  }

  // 将分批结果汇总成 renderScan 兼容的结构（单主机 {ports:[{port,open}]} / 多主机 {hosts:[{host,alive,ports}]}）。
  function buildScanView(recs, hosts, portList) {
    if (hosts.length === 1) {
      const rec = recs.get(hosts[0]);
      const ports = [...rec.ports.entries()].map(([port, open]) => ({ port, open }))
        .sort((a, b) => a.port - b.port);
      return { ports };
    }
    const hostViews = hosts.map((h) => {
      const rec = recs.get(h);
      const ports = [...rec.ports.entries()].filter(([, o]) => o).map(([p]) => p).sort((a, b) => a - b);
      return { host: h, alive: rec.alive, ports };
    });
    return { hosts: hostViews };
  }

  // 对目标主机做 TCP 端口扫描：GET /api/targets/{id}/scan?host=&ports=
  // 前端按「1 主机 × ≤12 端口」分批，每请求对应靶机一次 ≤24s 的脚本，保证每次请求 ≤30s 并展示进度。
  async function loadScan() {
    if (!state.current) return;
    const hostSpec = $('scanHost').value.trim();
    const portsSpec = $('scanPorts').value.trim();
    const status = $('scanStatus');
    const body = $('scanBody');
    if (!hostSpec) {
      status.textContent = '请填写目标主机';
      status.className = 'scan-status err';
      return;
    }
    if (!portsSpec) {
      status.textContent = '请填写端口';
      status.className = 'scan-status err';
      return;
    }
    let hosts, portList;
    try {
      hosts = expandHosts(hostSpec);
      portList = expandPorts(portsSpec);
    } catch (e) {
      status.textContent = '参数错误：' + e.message;
      status.className = 'scan-status err';
      return;
    }
    if (!hosts.length || !portList.length) {
      status.textContent = '目标或端口为空';
      status.className = 'scan-status err';
      return;
    }
    status.textContent = '扫描中…';
    status.className = 'scan-status';
    body.textContent = '';
    try {
      const portBatches = chunkArray(portList, SCAN_PORT_BATCH);
      const total = hosts.length * portBatches.length;
      let done = 0;
      let elapsedSum = 0;
      const recs = new Map();
      for (const h of hosts) recs.set(h, { ports: new Map(), alive: false });
      for (const h of hosts) {
        for (const pb of portBatches) {
          const q = '?host=' + encodeURIComponent(h) + '&ports=' + encodeURIComponent(pb.join(','));
          const d = await api('targets/' + encodeURIComponent(state.current.id) + '/scan' + q, { timeoutMs: SCAN_REQ_TIMEOUT });
          const ps = (d && Array.isArray(d.ports)) ? d.ports : [];
          const rec = recs.get(h);
          for (const p of ps) {
            const port = Number(p.port);
            rec.ports.set(port, !!p.open);
            if (p.open) rec.alive = true;
          }
          if (typeof d.elapsed === 'number') elapsedSum += d.elapsed;
          done++;
          status.textContent = '扫描中… ' + done + '/' + total + (hosts.length > 1 ? '（' + h + '）' : '');
          if (hosts.length > 1) renderScan(buildScanView(recs, hosts, portList), null);
        }
      }
      renderScan(buildScanView(recs, hosts, portList), hosts.length === 1 ? hostSpec : null);
      const openTotal = [...recs.values()].reduce((s, r) => s + [...r.ports.values()].filter(Boolean).length, 0);
      const aliveCount = [...recs.values()].filter((r) => r.alive).length;
      const elapsed = elapsedSum > 0 ? elapsedSum.toFixed(2) + 's' : '—';
      status.textContent = '扫描完成：' + (hosts.length > 1
        ? ('共 ' + hosts.length + ' 个目标，在线 ' + aliveCount + ' 个，开放端口 ' + openTotal + ' 个')
        : ('共 ' + portList.length + ' 个端口，开放 ' + openTotal + ' 个')) + '，用时 ' + elapsed;
      status.className = 'scan-status ok';
    } catch (err) {
      status.textContent = '扫描失败：' + err.message;
      status.className = 'scan-status err';
    }
  }

  // 渲染端口扫描结果到 #scanBody。兼容单主机（{host,ports}）与多主机（{hosts:[...]}）两种结构。
  function renderScan(d, host) {
    const body = $('scanBody');
    body.textContent = '';
    if (Array.isArray(d.hosts)) {
      if (!d.hosts.length) {
        body.appendChild(el('div', 'fs-hint', '（无数据）'));
        return;
      }
      const sorted = d.hosts.slice().sort((a, b) => (a.alive === b.alive) ? 0 : (a.alive ? -1 : 1));
      const tbl = el('table', 'sys-proc');
      const thead = el('tr', '');
      ['主机', '状态', '开放端口'].forEach((h) => thead.appendChild(el('th', '', h)));
      tbl.appendChild(thead);
      sorted.forEach((x) => {
        const ps = Array.isArray(x.ports) ? x.ports : [];
        const tr = el('tr', x.alive ? 'open-row' : '');
        tr.appendChild(el('td', 'mono', String(x.host || '-')));
        tr.appendChild(el('td', 'mono', x.alive ? '在线' : '离线'));
        tr.appendChild(el('td', 'mono', x.alive ? (ps.length ? ps.join(', ') : '（无开放端口）') : '—'));
        tbl.appendChild(tr);
      });
      const wrap = el('div', 'sys-proc-wrap');
      wrap.appendChild(tbl);
      body.appendChild(wrap);
      return;
    }
    // 单主机结果（旧结构）
    const ports = Array.isArray(d.ports) ? d.ports : [];
    if (!ports.length) {
      body.appendChild(el('div', 'fs-hint', '（无数据）'));
      return;
    }
    const open = ports.filter((p) => p.open);
    const sorted = ports.slice().sort((a, b) => (Number(a.port) || 0) - (Number(b.port) || 0));
    const tbl = el('table', 'sys-proc');
    const thead = el('tr', '');
    ['端口', '状态', '主机'].forEach((h) => thead.appendChild(el('th', '', h)));
    tbl.appendChild(thead);
    sorted.forEach((p) => {
      const tr = el('tr', p.open ? 'open-row' : '');
      tr.appendChild(el('td', 'mono', String(p.port)));
      tr.appendChild(el('td', 'mono', p.open ? '开放' : '关闭'));
      tr.appendChild(el('td', 'mono', String(host || '—')));
      tbl.appendChild(tr);
    });
    const wrap = el('div', 'sys-proc-wrap');
    wrap.appendChild(tbl);
    body.appendChild(wrap);
    const sum = el('div', 'fs-hint', '开放 ' + open.length + ' / ' + ports.length + ' 个端口' + (open.length ? '：' + open.map((p) => p.port).join(', ') : ''));
    body.appendChild(sum);
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
  // 解析用户在路径框里输入的目录并跳转：
  //   - Windows 绝对路径（如 C:\foo 或 C:/foo、UNC \\host\share）直接作为目标，不再与当前目录拼接；
  //   - 以 / 开头的类 Unix 绝对路径直接作为目标；
  //   - 其余按相对路径，基于当前目录拼接（分隔符沿用当前目录的风格）。
  function navigateFs(raw) {
    let dir = (raw || '').trim();
    if (!dir) {
      loadFs(state.fsPath);
      return;
    }
    if (/^[A-Za-z]:[\\/]/.test(dir) || dir.startsWith('\\\\') || dir.startsWith('/')) {
      loadFs(dir);
      return;
    }
    let base = state.fsPath;
    if (!base || base === '.') base = '';
    else base = base.replace(/[\\/]+$/, '');
    if (!base) {
      loadFs(dir);
      return;
    }
    const sep = base.includes('\\') ? '\\' : '/';
    loadFs(base + sep + dir);
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
      // 记录访问历史（去重、最新在前、最多保留 30 条）。
      if (cur) {
        state.fsHistory = [cur, ...state.fsHistory.filter((x) => x !== cur)].slice(0, 30);
      }
      list.textContent = '';
      if (!data.entries.length) {
        list.appendChild(el('li', 'fs-row fs-hint', '（空目录）'));
      }
      // 先展示子目录，再展示文件；同类按名称排序。
      data.entries.sort((a, b) => (Number(b.isDir) - Number(a.isDir)) || String(a.name).localeCompare(String(b.name)));
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

  // 隐形镜像元素：用与 textarea 相同的字体/宽度，测量某行软换行后占几行。
  let fsMirror = null;
  function fsMirrorEl(ta) {
    if (!fsMirror) {
      fsMirror = document.createElement('div');
      fsMirror.style.position = 'absolute';
      fsMirror.style.left = '-9999px';
      fsMirror.style.top = '0';
      fsMirror.style.visibility = 'hidden';
      document.body.appendChild(fsMirror);
    }
    const cs = getComputedStyle(ta);
    fsMirror.style.fontFamily = cs.fontFamily;
    fsMirror.style.fontSize = cs.fontSize;
    fsMirror.style.lineHeight = cs.lineHeight;
    fsMirror.style.whiteSpace = 'pre-wrap';
    fsMirror.style.overflowWrap = 'anywhere';
    fsMirror.style.width = Math.max(1, ta.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)) + 'px';
    return fsMirror;
  }

  // 根据编辑器内容重算左侧行号，并同步滚动位置（与 textarea 逐行对齐）。
  // 开启自动换行时，一个逻辑行可能占多显示行，行号需要按实际行数排版才能对齐。
  function syncFsGutter() {
    const ta = $('fsContent');
    const gut = $('fsGutter');
    const lines = ta.value.split('\n');
    let s = '';
    if (state.fsWrap && lines.length <= 2000) {
      const m = fsMirrorEl(ta);
      const lh = parseFloat(getComputedStyle(ta).lineHeight) || 20;
      for (let i = 0; i < lines.length; i++) {
        m.textContent = lines[i] || ' ';
        const rows = Math.max(1, Math.round(m.offsetHeight / lh));
        s += (i + 1) + '\n';
        for (let r = 1; r < rows; r++) s += '\n';
      }
    } else {
      for (let i = 1; i <= lines.length; i++) s += i + '\n';
    }
    gut.textContent = s;
    gut.scrollTop = ta.scrollTop;
  }

  // 应用自动换行设置：开启时软换行并隐藏行号栏，关闭时恢复逐行显示与行号。
  function applyFsWrap() {
    const ed = $('fsEditor');
    ed.classList.toggle('wrap', state.fsWrap);
    const btn = $('fsWrap');
    btn.classList.toggle('primary', state.fsWrap);
    btn.classList.toggle('ghost', !state.fsWrap);
    syncFsGutter();
  }

  // 读取文件到编辑器：GET /api/targets/{id}/fs/read?path=
  async function openFsFile(path, name) {
    try {
      const f = await api('targets/' + encodeURIComponent(state.current.id) + '/fs/read?path=' + encodeURIComponent(path));
      $('fsEditName').textContent = name + '  (' + f.size + ' B)';
      $('fsContent').value = b64decodeUtf8(f.base64);
      $('fsEditor').dataset.path = path;
      $('fsEditorBackdrop').classList.remove('hidden');
      $('fsEditor').classList.remove('hidden');
      applyFsWrap();
    } catch (err) {
      toast('读取失败：' + err.message);
    }
  }

  // 关闭文件编辑/查看弹窗。
  function closeFsEditor() {
    $('fsEditor').classList.add('hidden');
    $('fsEditorBackdrop').classList.add('hidden');
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
      closeFsEditor();
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
    $('fsEditorBackdrop').classList.remove('hidden');
    $('fsEditor').classList.remove('hidden');
    applyFsWrap();
  }

  // ---------- PHP 环境能力研判（独立页） ----------

  // 读取靶机 phpinfo 能力研判：GET /api/targets/{id}/phpinfo
  async function loadPhpInfo() {
    if (!state.current) return;
    const body = $('phpinfoBody');
    if (!body.childElementCount) body.appendChild(el('div', 'fs-hint', '加载中…'));
    try {
      const d = await api('targets/' + encodeURIComponent(state.current.id) + '/phpinfo');
      renderPhpInfo(d, body);
      $('phpinfoUpdated').textContent = '更新于 ' + new Date().toLocaleTimeString();
    } catch (err) {
      body.textContent = '';
      body.appendChild(el('div', 'fs-err', '加载失败：' + err.message));
    }
  }

  function stopPhpInfoAuto() {
    if (state.phpinfoTimer) { clearInterval(state.phpinfoTimer); state.phpinfoTimer = null; }
    const cb = $('phpinfoAuto');
    if (cb) cb.checked = false;
  }

  // 把 ini 值归一为布尔（'1'/'On'/'true' 为真，其余为假，空串视为未设置）。
  function iniBool(v) {
    return v === '1' || v === 'On' || v === 'on' || v === 'true' || v === 'yes';
  }

  function badge(kind, text) {
    return el('span', 'ph-badge ' + kind, text);
  }

  // 渲染 phpinfo 能力研判：先给结论横幅，再列配置项与禁用函数。
  function renderPhpInfo(d, body) {
    body.textContent = '';
    // ASP 靶机返回 kind:"asp"，走独立渲染；其余按 PHP 环境渲染。
    if (d.kind === 'asp') { renderAspEnv(d, body); return; }

    const anyExec = !!d.anyExec;
    const exec = d.execFunctions || {};

    // 结论横幅
    const banner = el('div', 'ph-banner ' + (anyExec ? 'ok' : 'err'));
    if (anyExec) {
      const enabled = Object.keys(exec).filter((k) => exec[k]);
      banner.appendChild(el('div', 'ph-banner-title', '✓ 可执行系统命令'));
      banner.appendChild(el('div', 'ph-banner-sub', '可用函数：' + enabled.join('、')));
    } else {
      banner.appendChild(el('div', 'ph-banner-title', '✗ 命令执行函数均被禁用'));
      banner.appendChild(el('div', 'ph-banner-sub', 'exec/system/passthru/shell_exec/popen/proc_open/pcntl_exec 全部不可用，只能做纯 PHP 逻辑或文件类操作'));
    }
    body.appendChild(banner);

    // 基本信息卡片
    const info = el('div', 'sys-cards');
    const basic = [
      ['PHP 版本', d.version || '—'],
      ['SAPI', d.sapi || '—'],
      ['操作系统', d.os || '—'],
      ['运行用户', d.user || '—'],
      ['Web 服务', d.serverSoftware || '—'],
      ['DOCUMENT_ROOT', d.docRoot || '—'],
    ];
    basic.forEach(([k, v]) => {
      const c = el('div', 'sys-card');
      c.appendChild(el('div', 'sys-card-title', k));
      c.appendChild(el('div', 'sys-card-val', String(v)));
      info.appendChild(c);
    });
    body.appendChild(info);

    // 命令执行函数逐一看板
    const fnCard = el('div', 'sys-card wide');
    fnCard.appendChild(el('div', 'sys-card-title', '命令执行函数可用性'));
    const fnRow = el('div', 'ph-fn-row');
    Object.keys(exec).forEach((k) => {
      const b = el('span', 'ph-fn ' + (exec[k] ? 'avail' : 'blocked'), k + (exec[k] ? ' ✓' : ' ✗'));
      fnRow.appendChild(b);
    });
    fnCard.appendChild(fnRow);
    body.appendChild(fnCard);

    // 受限配置项
    const cfgCard = el('div', 'sys-card wide');
    cfgCard.appendChild(el('div', 'sys-card-title', '受限 / 安全相关配置'));
    const rows = [
      ['disable_functions', (Array.isArray(d.disabledFunctions) ? d.disabledFunctions.join(', ') : '') || '（无）', d.disabledFunctions && d.disabledFunctions.length ? 'warn' : 'ok'],
      ['open_basedir', d.openBasedir || '（未限制）', d.openBasedir ? 'warn' : 'ok'],
      ['allow_url_include', d.allowUrlInclude, iniBool(d.allowUrlInclude) ? 'warn' : 'ok'],
      ['allow_url_fopen', d.allowUrlFopen, iniBool(d.allowUrlFopen) ? 'ok' : 'warn'],
      ['safe_mode', d.safeMode || '（无）', d.safeMode ? 'warn' : 'ok'],
      ['display_errors', d.displayErrors, iniBool(d.displayErrors) ? 'ok' : 'warn'],
      ['file_uploads', d.fileUploads, iniBool(d.fileUploads) ? 'ok' : 'warn'],
      ['upload_tmp_dir', d.uploadTmpDir || '（默认）', 'ok'],
    ];
    rows.forEach(([k, v, kind]) => {
      const r = el('div', 'sys-card-row');
      r.appendChild(el('span', 'sys-k', k));
      const right = el('span', 'sys-v');
      right.appendChild(badge(kind, kind === 'warn' ? '受限' : '正常'));
      right.appendChild(el('span', 'ph-cfg-val', ' ' + String(v)));
      r.appendChild(right);
      cfgCard.appendChild(r);
    });
    body.appendChild(cfgCard);

    // 禁用函数清单（缺失的能力）
    const df = Array.isArray(d.disabledFunctions) ? d.disabledFunctions : [];
    const dfCard = el('div', 'sys-card wide');
    dfCard.appendChild(el('div', 'sys-card-title', '被禁用的函数（共 ' + df.length + ' 个）'));
    if (!df.length) {
      dfCard.appendChild(el('div', 'fs-hint', '（disable_functions 为空，未禁用任何函数）'));
    } else {
      const wrap = el('div', 'ph-tag-wrap');
      df.forEach((fn) => wrap.appendChild(el('span', 'ph-tag', fn)));
      dfCard.appendChild(wrap);
    }
    body.appendChild(dfCard);

    // 已加载扩展
    const ext = Array.isArray(d.extensions) ? d.extensions : [];
    const extCard = el('div', 'sys-card wide');
    extCard.appendChild(el('div', 'sys-card-title', '已加载扩展（共 ' + ext.length + ' 个）'));
    const ewrap = el('div', 'ph-tag-wrap');
    ext.forEach((x) => ewrap.appendChild(el('span', 'ph-tag', x)));
    extCard.appendChild(ewrap);
    body.appendChild(extCard);
  }

  // 渲染 ASP 环境能力研判：结论横幅（能否跑命令）+ 基本信息 + COM 组件可用性看板。
  function renderAspEnv(d, body) {
    const anyExec = !!d.anyExec;
    const comps = d.execComponents || {};

    // 结论横幅
    const banner = el('div', 'ph-banner ' + (anyExec ? 'ok' : 'err'));
    if (anyExec) {
      banner.appendChild(el('div', 'ph-banner-title', '✓ 可执行系统命令（WScript.Shell 可用）'));
      banner.appendChild(el('div', 'ph-banner-sub', '可通过 cmd /c 执行命令；文件读写依赖 Scripting.FileSystemObject'));
    } else {
      banner.appendChild(el('div', 'ph-banner-title', '✗ 关键 COM 组件不可用'));
      banner.appendChild(el('div', 'ph-banner-sub', 'WScript.Shell 被禁用/缺失，无法稳定执行命令，仅能做受限的纯脚本逻辑'));
    }
    body.appendChild(banner);

    // 基本信息卡片
    const info = el('div', 'sys-cards');
    const basic = [
      ['脚本引擎', d.engine || '—'],
      ['操作系统', d.os || '—'],
      ['Web 服务', d.serverSoftware || '—'],
      ['物理路径', d.docRoot || '—'],
    ];
    basic.forEach(([k, v]) => {
      const c = el('div', 'sys-card');
      c.appendChild(el('div', 'sys-card-title', k));
      c.appendChild(el('div', 'sys-card-val', String(v)));
      info.appendChild(c);
    });
    body.appendChild(info);

    // COM 组件可用性看板
    const fnCard = el('div', 'sys-card wide');
    fnCard.appendChild(el('div', 'sys-card-title', '关键 COM 组件可用性'));
    const fnRow = el('div', 'ph-fn-row');
    Object.keys(comps).forEach((k) => {
      const b = el('span', 'ph-fn ' + (comps[k] ? 'avail' : 'blocked'), k + (comps[k] ? ' ✓' : ' ✗'));
      fnRow.appendChild(b);
    });
    fnCard.appendChild(fnRow);
    body.appendChild(fnCard);

    // 可用组件清单
    const list = Array.isArray(d.components) ? d.components : [];
    const extCard = el('div', 'sys-card wide');
    extCard.appendChild(el('div', 'sys-card-title', '可用组件（共 ' + list.length + ' 个）'));
    const ewrap = el('div', 'ph-tag-wrap');
    list.forEach((x) => ewrap.appendChild(el('span', 'ph-tag', x)));
    extCard.appendChild(ewrap);
    body.appendChild(extCard);
  }

  // ---------- 事件绑定 ----------

  function bind() {
    $('btnSettings').addEventListener('click', openSettings);
    $('saveSettings').addEventListener('click', saveSettings);
    $('uaMode').addEventListener('change', (ev) => {
      const isSpecified = ev.target.value === 'specified';
      $('uaValueWrap').hidden = !isSpecified;
      if (isSpecified && !$('uaValue').value.trim()) {
        $('uaValue').value = navigator.userAgent;
      }
    });
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
    $('infoRefresh').addEventListener('click', loadInfo);
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
    $('portsRefresh').addEventListener('click', loadPorts);
    $('portsAuto').addEventListener('change', (ev) => {
      stopPortsAuto();
      if (ev.target.checked) {
        loadPorts();
        state.portsTimer = setInterval(loadPorts, 3000);
      }
    });
    $('portsSearch').addEventListener('input', () => {
      if (state.current) renderPorts();
    });
    $('scanBtn').addEventListener('click', loadScan);
    $('scanHost').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') loadScan(); });
    $('scanPorts').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') loadScan(); });
    $('phpinfoRefresh').addEventListener('click', loadPhpInfo);
    $('phpinfoAuto').addEventListener('change', (ev) => {
      stopPhpInfoAuto();
      if (ev.target.checked) {
        loadPhpInfo();
        state.phpinfoTimer = setInterval(loadPhpInfo, 3000);
      }
    });
    $('fsUp').addEventListener('click', () => {
      const p = state.fsPath;
      // 根目录（/、\、盘符根 C:\）无法再向上。
      if (!p || p === '/' || p === '\\' || /^[A-Za-z]:[\\/]?$/.test(p)) return;
      const clean = p.replace(/[\\/]+$/, '');
      const i = Math.max(clean.lastIndexOf('/'), clean.lastIndexOf('\\'));
      // i===0 表示类 Unix 顶级目录（如 /etc，父目录为 /）；i<0 表示无分隔符，回退到当前目录。
      if (i <= 0) { loadFs(i === 0 ? '/' : '.'); return; }
      // 保留分隔符本身（如 C:\Windows -> C:\），否则会丢掉成 C: 这种非法盘符路径。
      loadFs(clean.slice(0, i + 1));
    });
    $('fsPath').addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        hideFsHistory();
        navigateFs($('fsPath').value);
      }
    });
    // 点击输入框时下拉展示访问过的目录，便于快速跳转。
    $('fsPath').addEventListener('focus', renderFsHistory);
    $('fsPath').addEventListener('click', (ev) => { ev.stopPropagation(); renderFsHistory(); });
    // 点击页面其它位置收起下拉。
    document.addEventListener('click', hideFsHistory);
    function renderFsHistory() {
      const box = $('fsHistory');
      if (!state.current || state.fsHistory.length === 0) { box.classList.add('hidden'); return; }
      box.textContent = '';
      state.fsHistory.forEach((p) => {
        const li = el('li', 'fs-hist-item', p);
        li.addEventListener('click', (ev) => {
          ev.stopPropagation();
          hideFsHistory();
          navigateFs(p);
        });
        box.appendChild(li);
      });
      box.classList.remove('hidden');
    }
    function hideFsHistory() { $('fsHistory').classList.add('hidden'); }
    $('fsNew').addEventListener('click', newFsFile);
    $('fsUpload').addEventListener('click', () => $('fsFileInput').click());
    $('fsFileInput').addEventListener('change', (ev) => {
      uploadFs(ev.target.files[0]);
      ev.target.value = '';
    });
    $('fsSave').addEventListener('click', saveFsFile);
    $('fsWrap').addEventListener('click', () => {
      state.fsWrap = !state.fsWrap;
      applyFsWrap();
    });
    $('fsEditClose').addEventListener('click', closeFsEditor);
    $('fsEditorBackdrop').addEventListener('click', closeFsEditor);
    document.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && !$('fsEditor').classList.contains('hidden')) closeFsEditor();
    });
    $('fsContent').addEventListener('input', syncFsGutter);
    $('fsContent').addEventListener('scroll', () => {
      $('fsGutter').scrollTop = $('fsContent').scrollTop;
    });
    // 窗口尺寸变化会改变软换行结果，弹窗打开时重排行号。
    window.addEventListener('resize', () => {
      if (!$('fsEditor').classList.contains('hidden')) syncFsGutter();
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
