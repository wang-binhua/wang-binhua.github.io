const $ = (selector) => document.querySelector(selector);
const colors = ['#4777b8', '#e39a55', '#62a77d', '#9c76bb', '#dc6c73', '#4fa7b1'];
const today = new Date().toISOString().slice(0, 10);
let kind = 'expense';
let categories = [];
let records = [];
let editingId = null;
let authMode = 'login';

$('#date').value = today;
$('#month').value = today.slice(0, 7);

const yuan = (amount) => `¥${Number(amount).toFixed(2)}`;
const escapeHtml = (text) => String(text).replace(/[&<>]/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;'
}[char]));

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  const data = response.status === 204 ? {} : await response.json();
  if (!response.ok) {
    if (response.status === 401 && !url.startsWith('/api/auth/')) {
      document.body.classList.add('locked');
      $('#authGate').hidden = false;
      setAuthMode('login');
      $('#authDescription').textContent = '登录已过期，请重新验证。';
    }
    throw new Error(data.error || '请求失败');
  }
  return data;
}

function setAuthMode(mode) {
  authMode = mode;
  const setup = mode === 'setup';
  const recovery = mode === 'recovery';
  $('#authTitle').textContent = setup ? '创建加密账本' : recovery ? '恢复账本' : '校园财务台登录';
  $('#authDescription').textContent = setup
    ? '设置至少 12 个字符的密码；已有账目会在确认后迁移并加密。'
    : recovery ? '输入恢复密钥并设置新密码。' : '请输入密码解锁账本。';
  $('#passwordLabel').firstChild.textContent = setup || recovery ? '新密码' : '登录密码';
  $('#authPassword').autocomplete = setup || recovery ? 'new-password' : 'current-password';
  $('#confirmLabel').hidden = !setup && !recovery;
  $('#recoveryLabel').hidden = !recovery;
  $('#recoverToggle').hidden = setup;
  $('#recoverToggle').textContent = recovery ? '返回登录' : '忘记密码？使用恢复密钥';
  $('#authSubmit').textContent = setup ? '创建并加密账本' : recovery ? '重设密码并解锁' : '登录';
  $('#authConfirm').required = setup || recovery;
  $('#recoveryKey').required = recovery;
}

async function unlockApp() {
  $('#recoveryNotice').hidden = true;
  $('#authForm').hidden = false;
  document.body.classList.remove('locked');
  const data = await api('/api/categories');
  categories = data.categories;
  renderCategories();
  await load();
}

function renderCategories() {
  const visible = categories.filter((category) => category.type === kind);
  $('#category').innerHTML = visible.map((category) =>
    `<option value="${category.id}">${escapeHtml(category.name)}</option>`
  ).join('');
}

function renderChart(items, total) {
  $('#bar').innerHTML = items.map((item, index) =>
    `<i class="slice" style="width:${total ? item.amount / total * 100 : 0}%;background:${colors[index % colors.length]}"></i>`
  ).join('');
  $('#stats').innerHTML = items.length ? items.map((item, index) =>
    `<div class="stat"><span><i class="dot" style="background:${colors[index % colors.length]}"></i>${escapeHtml(item.name)}</span><b>${yuan(item.amount)}</b></div>`
  ).join('') : '本月暂无支出。';
}

function renderRows(items) {
  records = items;
  $('#rows').innerHTML = items.length ? items.map((item) =>
    `<tr><td>${item.date}</td><td class="${item.type}">${item.type === 'income' ? '收入' : '支出'}</td><td>${escapeHtml(item.category)}</td><td>${escapeHtml(item.note)}</td><td>${item.type === 'income' ? '+' : '-'}${yuan(item.amount)}</td><td><button class="edit" data-id="${item.id}">编辑</button><button class="delete" data-id="${item.id}">删除</button></td></tr>`
  ).join('') : '<tr><td colspan="6">暂无账目</td></tr>';

  document.querySelectorAll('.delete').forEach((button) => button.onclick = async () => {
    if (confirm('删除这条账目？')) {
      await api(`/api/transactions/${button.dataset.id}`, { method: 'DELETE' });
      await load();
    }
  });
  document.querySelectorAll('.edit').forEach((button) => button.onclick = () => beginEdit(Number(button.dataset.id)));
}

function renderBudgets(items) {
  $('#budgets').innerHTML = items.map((item) =>
    `<label class="budget">${escapeHtml(item.category)}<input data-id="${item.categoryId}" type="number" min="0" step="1" value="${item.amount}"></label>`
  ).join('');
}

function beginEdit(id) {
  const item = records.find((record) => record.id === id);
  if (!item) return;
  editingId = id;
  kind = item.type;
  $('#date').value = item.date;
  $('#amount').value = item.amount;
  $('#note').value = item.note;
  document.querySelectorAll('[data-type]').forEach((button) => button.classList.toggle('on', button.dataset.type === kind));
  renderCategories();
  $('#category').value = String(item.categoryId);
  $('#editHint').textContent = `正在编辑编号 #${id}；修改后点击“保存”。`;
  $('.primary').textContent = '保存修改';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function load() {
  const month = $('#month').value;
  const [dashboard, transactionData, budgetData] = await Promise.all([
    api(`/api/dashboard?month=${month}`),
    api(`/api/transactions?month=${month}`),
    api(`/api/budgets?month=${month}`)
  ]);
  $('#income').textContent = yuan(dashboard.income);
  $('#expense').textContent = yuan(dashboard.expense);
  $('#balance').textContent = yuan(dashboard.balance);
  $('#availableBalance').textContent = yuan(dashboard.availableBalance);
  $('#budget').textContent = dashboard.budget ? `${yuan(dashboard.expense)} / ${yuan(dashboard.budget)}` : '未设置';
  renderChart(dashboard.categories, dashboard.expense);
  renderRows(transactionData.transactions);
  renderBudgets(budgetData.budgets);
}

document.querySelectorAll('[data-type]').forEach((button) => button.onclick = () => {
  kind = button.dataset.type;
  editingId = null;
  $('#editHint').textContent = '';
  $('.primary').textContent = '保存';
  document.querySelectorAll('[data-type]').forEach((other) => other.classList.toggle('on', other === button));
  renderCategories();
});

$('#form').onsubmit = async (event) => {
  event.preventDefault();
  const payload = {
    date: $('#date').value,
    type: kind,
    categoryId: Number($('#category').value),
    amount: Number($('#amount').value),
    note: $('#note').value
  };
  try {
    await api(editingId ? `/api/transactions/${editingId}` : '/api/transactions', {
      method: editingId ? 'PUT' : 'POST', body: JSON.stringify(payload)
    });
    editingId = null;
    $('#editHint').textContent = '';
    $('.primary').textContent = '保存';
    $('#amount').value = '';
    $('#note').value = '';
    await load();
  } catch (error) { alert(error.message); }
};

$('#save').onclick = async () => {
  const month = $('#month').value;
  try {
    await Promise.all([...document.querySelectorAll('#budgets input')].map((input) =>
      api('/api/budgets', { method: 'PUT', body: JSON.stringify({ month, categoryId: Number(input.dataset.id), amount: Number(input.value) }) })
    ));
    await load();
  } catch (error) { alert(error.message); }
};

$('#setBalance').onclick = async () => {
  const value = prompt('请输入现在实际可支配的总金额（元）。已有账目将作为当前余额基准，不会再次扣减；之后新增的收入和支出会自动计入。');
  if (value === null) return;
  if (!/^\d{1,8}(?:\.\d{1,2})?$/.test(value.trim()) ||
      !Number.isFinite(Number(value)) || Number(value) > 10000000) {
    alert('请输入 0 到 10000000 之间、最多两位小数的金额。');
    return;
  }
  try {
    await api('/api/balance', { method: 'PUT', body: JSON.stringify({ amount: Number(value) }) });
    await load();
  } catch (error) { alert(error.message); }
};

$('#addCategory').onclick = async () => {
  const name = prompt(`新增${kind === 'income' ? '收入' : '支出'}类别：`);
  if (!name || !name.trim()) return;
  try {
    const created = await api('/api/categories', {
      method: 'POST', body: JSON.stringify({ name: name.trim(), type: kind })
    });
    categories.push(created);
    renderCategories();
    $('#category').value = String(created.id);
  } catch (error) { alert(error.message); }
};

$('#download').onclick = () => { window.location.href = `/api/export?month=${$('#month').value}`; };
$('#month').onchange = load;

$('#authForm').onsubmit = async (event) => {
  event.preventDefault();
  const password = $('#authPassword').value;
  const confirmation = $('#authConfirm').value;
  if (password.length < 12 || ((authMode === 'setup' || authMode === 'recovery') && password !== confirmation)) {
    $('#authDescription').textContent = password.length < 12
      ? '密码至少需要 12 个字符。' : '两次输入的密码不一致。';
    return;
  }
  try {
    if (authMode === 'setup') {
      const result = await api('/api/auth/setup', { method: 'POST', body: JSON.stringify({ password }) });
      $('#recoveryDisplay').value = result.recoveryKey;
      $('#authForm').hidden = true;
      $('#recoveryNotice').hidden = false;
    } else if (authMode === 'recovery') {
      const result = await api('/api/auth/recover', {
        method: 'POST',
        body: JSON.stringify({ recoveryKey: $('#recoveryKey').value, password, confirmation })
      });
      $('#recoveryDisplay').value = result.recoveryKey;
      $('#authForm').hidden = true;
      $('#recoveryNotice').hidden = false;
    } else {
      await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ password }) });
      await unlockApp();
    }
    $('#authPassword').value = '';
    $('#authConfirm').value = '';
    $('#recoveryKey').value = '';
  } catch (error) {
    $('#authDescription').textContent = error.message;
  }
};

$('#recoverToggle').onclick = () => {
  setAuthMode(authMode === 'recovery' ? 'login' : 'recovery');
  $('#authPassword').value = '';
  $('#authConfirm').value = '';
  $('#recoveryKey').value = '';
};

$('#recoveryContinue').onclick = async () => {
  try {
    await unlockApp();
    $('#recoveryDisplay').value = '';
  } catch (error) {
    $('#authDescription').textContent = error.message;
  }
};

$('#logout').onclick = async () => {
  try {
    await api('/api/auth/logout', { method: 'POST', body: '{}' });
    document.body.classList.add('locked');
    setAuthMode('login');
    $('#authDescription').textContent = '账本已锁定，请重新登录。';
  } catch (error) {
    alert(error.message);
  }
};

api('/api/auth/status').then((status) => {
  setAuthMode(status.initialized ? 'login' : 'setup');
}).catch((error) => {
  $('#authDescription').textContent = error.message;
});
