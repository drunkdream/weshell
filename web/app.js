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
      li.appendChild(el('span', 'tname', t.name));
      li.appendChild(el('span', 'turl', t.url));
      li.addEventListener('click', () => selectTarget(t.id));
      list.appendChild(li);
    });
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
