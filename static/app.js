// awg-web — фронтенд. Данные загружаются ТОЛЬКО по явному действию:
// при первой загрузке страницы и по кнопке "Обновить" — никакого
// автообновления по таймеру, как и в исходном bash-скрипте.

(() => {
  const state = {
    users: [],
    summary: null,
    fetchedAt: null,
    includeNever: false,
    search: "",
  };

  const els = {
    refreshBtn: document.getElementById("refreshBtn"),
    themeToggle: document.getElementById("themeToggle"),
    fetchedAt: document.getElementById("fetchedAt"),
    containerName: document.getElementById("containerName"),
    searchInput: document.getElementById("searchInput"),
    includeNeverToggle: document.getElementById("includeNeverToggle"),
    tableBody: document.getElementById("tableBody"),
    statTotal: document.getElementById("statTotal"),
    statActive: document.getElementById("statActive"),
    statBlocked: document.getElementById("statBlocked"),
    statNever: document.getElementById("statNever"),
    toastStack: document.getElementById("toastStack"),
    confirmOverlay: document.getElementById("confirmOverlay"),
    confirmTitle: document.getElementById("confirmTitle"),
    confirmText: document.getElementById("confirmText"),
    confirmOk: document.getElementById("confirmOk"),
    confirmCancel: document.getElementById("confirmCancel"),
  };

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showToast(message, isError) {
    const el = document.createElement("div");
    el.className = "toast" + (isError ? " toast--error" : "");
    el.textContent = message;
    els.toastStack.appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }

  async function loadUsers() {
    els.refreshBtn.disabled = true;
    els.tableBody.innerHTML = '<tr><td colspan="7" class="empty-state">Загрузка…</td></tr>';
    try {
      const url = "/api/users?includeNever=" + (state.includeNever ? "true" : "false");
      const res = await fetch(url, { credentials: "same-origin" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || ("HTTP " + res.status));
      }
      const data = await res.json();
      state.users = data.users || [];
      state.summary = data.summary || null;
      state.fetchedAt = data.fetchedAt || null;
      els.containerName.textContent = "контейнер: " + (data.container || "—");
      render();
    } catch (e) {
      els.tableBody.innerHTML =
        '<tr><td colspan="7" class="empty-state">Не удалось загрузить данные: ' +
        escapeHtml(e.message) + "</td></tr>";
      showToast("Ошибка загрузки: " + e.message, true);
    } finally {
      els.refreshBtn.disabled = false;
    }
  }

  function render() {
    if (state.summary) {
      els.statTotal.textContent = state.summary.total;
      els.statActive.textContent = state.summary.active;
      els.statBlocked.textContent = state.summary.blocked;
      els.statNever.textContent = state.summary.neverSeen;
    }
    if (state.fetchedAt) {
      const d = new Date(state.fetchedAt);
      els.fetchedAt.textContent = "данные на " + d.toLocaleTimeString("ru-RU");
    }

    const q = state.search.trim().toLowerCase();
    const filtered = state.users.filter((u) => {
      if (!q) return true;
      return (
        u.name.toLowerCase().includes(q) ||
        u.ip.toLowerCase().includes(q)
      );
    });

    if (filtered.length === 0) {
      els.tableBody.innerHTML =
        '<tr><td colspan="7" class="empty-state">Никого не найдено</td></tr>';
      return;
    }

    els.tableBody.innerHTML = filtered.map(rowHtml).join("");

    // навешиваем обработчики на кнопки действий
    els.tableBody.querySelectorAll("[data-action]").forEach((btn) => {
      btn.addEventListener("click", onActionClick);
    });
  }

  function rowHtml(u) {
    const nameClass = u.name === "—" ? "name-cell name-cell--empty" : "name-cell";
    const hsClass = u.neverSeen ? "hs-cell hs-cell--never" : "hs-cell";

    let statusHtml;
    let actionHtml;
    if (u.blocked) {
      statusHtml =
        '<span class="status-pill status-pill--blocked">' +
        '<span class="status-dot status-dot--blocked"></span>Заблокирован</span>';
      actionHtml =
        '<button class="btn btn--row btn--row-unblock" data-action="unblock" data-ip="' +
        u.ip + '" data-name="' + escapeHtml(u.name) + '">Включить</button>';
    } else {
      const liveClass = u.recentlyActive ? " status-dot--live" : "";
      statusHtml =
        '<span class="status-pill status-pill--active">' +
        '<span class="status-dot status-dot--active' + liveClass + '"></span>Активен</span>';
      actionHtml =
        '<button class="btn btn--row btn--row-block" data-action="block" data-ip="' +
        u.ip + '" data-name="' + escapeHtml(u.name) + '">Отключить</button>';
    }

    return (
      "<tr>" +
      '<td class="col-num">' + u.num + "</td>" +
      '<td class="' + nameClass + '">' + escapeHtml(u.name) + "</td>" +
      '<td class="ip-cell">' + escapeHtml(u.ip) + "</td>" +
      '<td class="endpoint-cell">' + escapeHtml(u.endpoint) + "</td>" +
      '<td class="' + hsClass + '">' + escapeHtml(u.handshake) + "</td>" +
      "<td>" + statusHtml + "</td>" +
      '<td class="col-action">' + actionHtml + "</td>" +
      "</tr>"
    );
  }

  function onActionClick(e) {
    const btn = e.currentTarget;
    const action = btn.dataset.action;
    const ip = btn.dataset.ip;
    const name = btn.dataset.name;

    if (action === "block") {
      openConfirm(
        "Отключить пользователя",
        "Заблокировать «" + name + "» (" + ip + ")? Трафик с этого IP будет дропаться на уровне iptables.",
        () => performAction("block", ip)
      );
    } else {
      openConfirm(
        "Включить пользователя",
        "Снять блокировку с «" + name + "» (" + ip + ")?",
        () => performAction("unblock", ip)
      );
    }
  }

  async function performAction(action, ip) {
    try {
      const res = await fetch("/api/users/" + encodeURIComponent(ip) + "/" + action, {
        method: "POST",
        credentials: "same-origin",
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || ("HTTP " + res.status));
      }
      showToast(action === "block" ? "Пользователь отключён" : "Пользователь включён", false);
      // обновляем локально статус без полного перезапроса всех данных,
      // как и в bash-версии — полный список подтянется по кнопке "Обновить"
      const u = state.users.find((x) => x.ip === ip);
      if (u) u.blocked = action === "block";
      render();
    } catch (e) {
      showToast("Не удалось выполнить действие: " + e.message, true);
    }
  }

  // ---- confirm modal ----
  let pendingConfirm = null;

  function openConfirm(title, text, onConfirm) {
    els.confirmTitle.textContent = title;
    els.confirmText.textContent = text;
    pendingConfirm = onConfirm;
    els.confirmOverlay.classList.add("is-open");
  }
  function closeConfirm() {
    els.confirmOverlay.classList.remove("is-open");
    pendingConfirm = null;
  }
  els.confirmCancel.addEventListener("click", closeConfirm);
  els.confirmOverlay.addEventListener("click", (e) => {
    if (e.target === els.confirmOverlay) closeConfirm();
  });
  els.confirmOk.addEventListener("click", () => {
    const fn = pendingConfirm;
    closeConfirm();
    if (fn) fn();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeConfirm();
  });

  // ---- тема (тёмная/светлая) ----
  els.themeToggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    const next = current === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("awg-theme", next);
  });

  // ---- events ----
  els.refreshBtn.addEventListener("click", loadUsers);
  els.searchInput.addEventListener("input", (e) => {
    state.search = e.target.value;
    render();
  });
  els.includeNeverToggle.addEventListener("change", (e) => {
    state.includeNever = e.target.checked;
    loadUsers();
  });

  // первичная загрузка при открытии страницы
  loadUsers();
})();
