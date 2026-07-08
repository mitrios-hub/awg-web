// awg-web — фронтенд. Данные загружаются по явному действию (кнопка
// "Обновить") либо, если включён чекбокс "Авто (10с)", по таймеру.

(() => {
  const state = {
    users: [],
    summary: null,
    fetchedAt: null,
    includeNever: false,
    search: "",
    statusFilter: "all", // "all" | "active" | "blocked"
    autoRefresh: false,
    autoRefreshTimer: null,
  };

  const AUTO_REFRESH_MS = 10000;

  const els = {
    refreshBtn: document.getElementById("refreshBtn"),
    autoRefreshToggle: document.getElementById("autoRefreshToggle"),
    themeToggle: document.getElementById("themeToggle"),
    fetchedAt: document.getElementById("fetchedAt"),
    containerName: document.getElementById("containerName"),
    appVersion: document.getElementById("appVersion"),
    searchInput: document.getElementById("searchInput"),
    statusFilter: document.getElementById("statusFilter"),
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
    reissueOverlay: document.getElementById("reissueOverlay"),
    reissueTitle: document.getElementById("reissueTitle"),
    reissueSubtitle: document.getElementById("reissueSubtitle"),
    reissueQr: document.getElementById("reissueQr"),
    reissueDownload: document.getElementById("reissueDownload"),
    reissueCopy: document.getElementById("reissueCopy"),
    reissueClose: document.getElementById("reissueClose"),
    addBtn: document.getElementById("addBtn"),
    addOverlay: document.getElementById("addOverlay"),
    addInput: document.getElementById("addInput"),
    addOk: document.getElementById("addOk"),
    addCancel: document.getElementById("addCancel"),
  };

  // ---- автообновление по таймеру (10 сек) ----
  function stopAutoRefresh() {
    if (state.autoRefreshTimer) {
      clearInterval(state.autoRefreshTimer);
      state.autoRefreshTimer = null;
    }
  }

  function startAutoRefresh() {
    stopAutoRefresh();
    state.autoRefreshTimer = setInterval(() => {
      if (document.hidden) return; // не грузим сервер, пока вкладка не активна
      loadUsers();
    }, AUTO_REFRESH_MS);
  }

  function setAutoRefresh(enabled) {
    state.autoRefresh = enabled;
    localStorage.setItem("awg-autorefresh", enabled ? "1" : "0");
    if (enabled) {
      startAutoRefresh();
    } else {
      stopAutoRefresh();
    }
  }

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
    setTimeout(() => el.remove(), isError ? 8000 : 4000);
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
      els.appVersion.textContent = data.version ? "v" + data.version : "";
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

  // rowEls — соответствие ip → { tr, sig } для точечного обновления DOM.
  // Ключ — IP (уникален на пира и уже используется как data-ip). Благодаря
  // этому при обновлении данных перерисовываются только реально изменившиеся
  // строки, а неизменившиеся сохраняют свой DOM-узел (нет мигания, не
  // пересоздаются кнопки/картинки).
  const rowEls = new Map();

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
      if (state.statusFilter === "online" && !u.recentlyActive) return false;
      if (state.statusFilter === "blocked" && !u.blocked) return false;
      if (!q) return true;
      return (
        u.name.toLowerCase().includes(q) ||
        u.ip.toLowerCase().includes(q)
      );
    });

    if (filtered.length === 0) {
      rowEls.clear();
      els.tableBody.innerHTML =
        '<tr><td colspan="7" class="empty-state">Никого не найдено</td></tr>';
      return;
    }

    // Keyed-реконсиляция: строим фрагмент в нужном порядке, переиспользуя
    // существующие <tr> и обновляя их содержимое только при изменении данных.
    const frag = document.createDocumentFragment();
    const seen = new Set();

    for (const u of filtered) {
      seen.add(u.ip);
      const sig = signature(u);
      let entry = rowEls.get(u.ip);
      if (!entry) {
        const tr = document.createElement("tr");
        tr.dataset.ip = u.ip;
        tr.innerHTML = rowInnerHtml(u);
        entry = { tr, sig };
        rowEls.set(u.ip, entry);
      } else if (entry.sig !== sig) {
        entry.tr.innerHTML = rowInnerHtml(u);
        entry.sig = sig;
      }
      frag.appendChild(entry.tr); // перенос существующего узла сохраняет его DOM
    }

    // выкидываем строки, которых больше нет в наборе
    for (const ip of Array.from(rowEls.keys())) {
      if (!seen.has(ip)) rowEls.delete(ip);
    }

    els.tableBody.replaceChildren(frag);
  }

  // signature — строка из полей, влияющих на отображение строки. Если она не
  // изменилась, строку не трогаем.
  function signature(u) {
    return [
      u.num, u.name, u.ip, u.endpoint, u.handshake,
      u.neverSeen ? 1 : 0, u.blocked ? 1 : 0, u.recentlyActive ? 1 : 0,
    ].join("|");
  }

  // rowInnerHtml — содержимое строки (набор <td>) без обёртки <tr>.
  function rowInnerHtml(u) {
    const nameClass = u.name === "—" ? "name-cell name-cell--empty" : "name-cell";
    const hsClass = u.neverSeen ? "hs-cell hs-cell--never" : "hs-cell";

    let statusHtml;
    let actionHtml;
    const reissueBtn =
      '<button class="btn btn--row btn--row-reissue" data-action="reissue" data-ip="' +
      u.ip + '" data-name="' + escapeHtml(u.name) + '">Перевыпустить</button>';
    const deleteBtn =
      '<button class="btn btn--row btn--row-delete" data-action="delete" data-ip="' +
      u.ip + '" data-name="' + escapeHtml(u.name) + '">Удалить</button>';

    if (u.blocked) {
      statusHtml =
        '<span class="status-pill status-pill--blocked">' +
        '<span class="status-dot status-dot--blocked"></span>Заблокирован</span>';
      actionHtml =
        '<div class="row-actions">' +
        '<button class="btn btn--row btn--row-unblock" data-action="unblock" data-ip="' +
        u.ip + '" data-name="' + escapeHtml(u.name) + '">Включить</button>' +
        reissueBtn +
        deleteBtn +
        "</div>";
    } else {
      const liveClass = u.recentlyActive ? " status-dot--live" : "";
      statusHtml =
        '<span class="status-pill status-pill--active">' +
        '<span class="status-dot status-dot--active' + liveClass + '"></span>Активен</span>';
      actionHtml =
        '<div class="row-actions">' +
        '<button class="btn btn--row btn--row-block" data-action="block" data-ip="' +
        u.ip + '" data-name="' + escapeHtml(u.name) + '">Отключить</button>' +
        reissueBtn +
        deleteBtn +
        "</div>";
    }

    return (
      '<td class="col-num">' + u.num + "</td>" +
      '<td class="' + nameClass + '">' + escapeHtml(u.name) + "</td>" +
      '<td class="ip-cell">' + escapeHtml(u.ip) + "</td>" +
      '<td class="endpoint-cell">' + escapeHtml(u.endpoint) + "</td>" +
      '<td class="' + hsClass + '">' + escapeHtml(u.handshake) + "</td>" +
      "<td>" + statusHtml + "</td>" +
      '<td class="col-action">' + actionHtml + "</td>"
    );
  }

  function onActionClick(btn) {
    const action = btn.dataset.action;
    const ip = btn.dataset.ip;
    const name = btn.dataset.name;

    if (action === "block") {
      openConfirm(
        "Отключить пользователя",
        "Заблокировать «" + name + "» (" + ip + ")? Трафик с этого IP будет дропаться на уровне iptables.",
        () => performAction("block", ip)
      );
    } else if (action === "unblock") {
      openConfirm(
        "Включить пользователя",
        "Снять блокировку с «" + name + "» (" + ip + ")?",
        () => performAction("unblock", ip)
      );
    } else if (action === "reissue") {
      openConfirm(
        "Перевыпустить конфиг",
        "Сгенерировать новую пару ключей для «" + name + "» (" + ip + ") и заменить публичный ключ на сервере? " +
          "Старый конфиг/QR (если он у клиента ещё остался) сразу перестанет работать — потребуется установить новый.",
        () => performReissue(ip)
      );
    } else if (action === "delete") {
      openConfirm(
        "Удалить клиента",
        "Удалить «" + name + "» (" + ip + ")? Пир будет убран из wg0.conf и clientsTable, IP освободится. " +
          "Действие необратимо — если клиент нужен снова, придётся создать заново.",
        () => performDelete(ip)
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

  let lastReissue = null;

  // showClientConfig — общий вывод результата (конфиг + QR) в модалку,
  // используется и перевыпуском, и добавлением клиента.
  function showClientConfig(data, title, subtitle) {
    lastReissue = data;
    els.reissueTitle.textContent = title;
    els.reissueSubtitle.textContent = subtitle;
    els.reissueQr.src = "data:image/png;base64," + data.qrPngBase64;
    els.reissueOverlay.classList.add("is-open");
    if (data.warning) showToast(data.warning, true);
  }

  async function performReissue(ip) {
    try {
      const res = await fetch("/api/users/" + encodeURIComponent(ip) + "/reissue", {
        method: "POST",
        credentials: "same-origin",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
      showClientConfig(data, "Клиент перевыпущен", data.name + " (" + data.ip + ") — новый конфиг готов");
      showToast("Клиент перевыпущен", false);
      loadUsers(); // clientId сменился — подтягиваем актуальные данные
    } catch (e) {
      showToast("Не удалось перевыпустить: " + e.message, true);
    }
  }

  async function performAddClient(name) {
    try {
      const res = await fetch("/api/clients", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
      showClientConfig(data, "Клиент добавлен", data.name + " (" + data.ip + ") — конфиг готов");
      showToast("Клиент добавлен: " + data.name + " (" + data.ip + ")", false);
      loadUsers();
    } catch (e) {
      showToast("Не удалось добавить клиента: " + e.message, true);
    }
  }

  async function performDelete(ip) {
    try {
      const res = await fetch("/api/users/" + encodeURIComponent(ip) + "/delete", {
        method: "POST",
        credentials: "same-origin",
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || ("HTTP " + res.status));
      }
      showToast("Клиент удалён", false);
      loadUsers();
    } catch (e) {
      showToast("Не удалось удалить: " + e.message, true);
    }
  }

  els.reissueDownload.addEventListener("click", () => {
    if (!lastReissue) return;
    const blob = new Blob([lastReissue.configText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = lastReissue.filename || "client.conf";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  });

  els.reissueCopy.addEventListener("click", async () => {
    if (!lastReissue) return;
    try {
      await navigator.clipboard.writeText(lastReissue.configText);
      showToast("Текст конфига скопирован", false);
    } catch (e) {
      showToast("Не удалось скопировать: " + e.message, true);
    }
  });

  function closeReissue() {
    els.reissueOverlay.classList.remove("is-open");
    lastReissue = null;
  }
  els.reissueClose.addEventListener("click", closeReissue);
  els.reissueOverlay.addEventListener("click", (e) => {
    if (e.target === els.reissueOverlay) closeReissue();
  });

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
    if (e.key === "Escape") {
      closeConfirm();
      closeReissue();
      closeAdd();
    }
  });

  // ---- модалка добавления клиента ----
  function openAdd() {
    els.addInput.value = "";
    els.addOverlay.classList.add("is-open");
    setTimeout(() => els.addInput.focus(), 0);
  }
  function closeAdd() {
    els.addOverlay.classList.remove("is-open");
  }
  function submitAdd() {
    const name = els.addInput.value.trim();
    if (!name) {
      els.addInput.focus();
      return;
    }
    closeAdd();
    performAddClient(name);
  }
  els.addBtn.addEventListener("click", openAdd);
  els.addCancel.addEventListener("click", closeAdd);
  els.addOk.addEventListener("click", submitAdd);
  els.addOverlay.addEventListener("click", (e) => {
    if (e.target === els.addOverlay) closeAdd();
  });
  els.addInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submitAdd();
    else if (e.key === "Escape") closeAdd();
  });

  // ---- фильтр статуса ----
  els.statusFilter.addEventListener("click", (e) => {
    const btn = e.target.closest(".segmented__btn");
    if (!btn) return;
    state.statusFilter = btn.dataset.status;
    els.statusFilter.querySelectorAll(".segmented__btn").forEach((b) => {
      b.classList.toggle("is-active", b === btn);
    });
    render();
  });

  // ---- тема (тёмная/светлая) ----
  els.themeToggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    const next = current === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("awg-theme", next);
  });

  // ---- events ----
  // делегирование: один обработчик на всю таблицу вместо перенавешивания на
  // каждую кнопку при каждом рендере
  els.tableBody.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (btn && els.tableBody.contains(btn)) onActionClick(btn);
  });
  els.refreshBtn.addEventListener("click", loadUsers);
  els.searchInput.addEventListener("input", (e) => {
    state.search = e.target.value;
    render();
  });
  els.includeNeverToggle.addEventListener("change", (e) => {
    state.includeNever = e.target.checked;
    loadUsers();
  });
  els.autoRefreshToggle.addEventListener("change", (e) => {
    setAutoRefresh(e.target.checked);
  });
  document.addEventListener("visibilitychange", () => {
    // при возврате на вкладку сразу подтягиваем свежие данные,
    // если автообновление включено
    if (!document.hidden && state.autoRefresh) {
      loadUsers();
    }
  });

  // восстановление сохранённого состояния автообновления
  if (localStorage.getItem("awg-autorefresh") === "1") {
    els.autoRefreshToggle.checked = true;
    setAutoRefresh(true);
  }

  // первичная загрузка при открытии страницы
  loadUsers();
})();
