// awg-web — фронтенд. Данные подтягиваются автоматически раз в секунду и
// применяются к таблице точечно (без полной перерисовки): меняется только то,
// что реально изменилось — текст handshake/трафика, индикатор онлайн, а строки
// плавно добавляются/удаляются при подключении/отключении клиентов.

(() => {
  const state = {
    users: [],
    summary: null,
    fetchedAt: null,
    includeNever: false,
    search: "",
    statusFilter: "all", // "all" | "online" | "blocked"
  };

  const REFRESH_MS = 1000;

  // иконки для компактных кнопок в строках
  const ICONS = {
    block: '<svg class="icon" viewBox="0 0 20 20"><circle cx="10" cy="10" r="6" fill="currentColor"/></svg>',
    unblock: '<svg class="icon" viewBox="0 0 20 20"><circle cx="10" cy="10" r="6" fill="currentColor"/></svg>',
    reissue: '<svg class="icon" viewBox="0 0 20 20" fill="none"><path d="M4 10a6 6 0 0 1 10.2-4.3M16 10a6 6 0 0 1-10.2 4.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M14 3v3h-3M6 17v-3h3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    delete: '<svg class="icon" viewBox="0 0 20 20" fill="none"><path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  };

  // humanizeBytes — компактный объём (Б/КБ/МБ/ГБ/ТБ), число всегда < 1000.
  function humanizeBytes(n) {
    if (n == null || n < 0) return "—";
    const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let f = n, i = 0;
    while (f >= 1000 && i < units.length - 1) { f /= 1024; i++; }
    const val = i === 0 ? String(Math.round(f)) : (f >= 100 ? f.toFixed(0) : f.toFixed(1));
    return val + " " + units[i];
  }

  const els = {
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

  // ---- загрузка данных ----
  // Первый вызов показывает плейсхолдер "Загрузка…"; последующие (фоновый
  // опрос раз в секунду) молча обновляют таблицу и при ошибке НЕ трогают её —
  // держим последние удачные данные. inFlight не даёт запросам наслаиваться.
  let firstLoad = true;
  let inFlight = false;

  async function loadUsers() {
    if (inFlight) return;
    inFlight = true;
    if (firstLoad) {
      els.tableBody.innerHTML = '<tr><td colspan="8" class="empty-state">Загрузка…</td></tr>';
    }
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
      firstLoad = false;
    } catch (e) {
      if (firstLoad) {
        els.tableBody.innerHTML =
          '<tr><td colspan="8" class="empty-state">Не удалось загрузить данные: ' +
          escapeHtml(e.message) + "</td></tr>";
        showToast("Ошибка загрузки: " + e.message, true);
      }
    } finally {
      inFlight = false;
    }
  }

  // rowEls — ip → { tr, ссылки на ячейки, закэшированные значения }. Строим
  // строку один раз, дальше правим только изменившиеся ячейки — без перезаписи
  // innerHTML всей строки (нет мигания, не пересоздаются кнопки, не сбрасывается
  // анимация пульса).
  const rowEls = new Map();

  function statusPillHtml(u) {
    if (u.blocked) {
      return '<span class="status-pill status-pill--blocked">' +
        '<span class="status-dot status-dot--blocked"></span>Заблокирован</span>';
    }
    const live = u.recentlyActive ? " status-dot--live" : "";
    return '<span class="status-pill status-pill--active">' +
      '<span class="status-dot status-dot--active' + live + '"></span>Активен</span>';
  }

  function actionCellHtml(u) {
    const dataAttr = ' data-ip="' + u.ip + '" data-name="' + escapeHtml(u.name) + '"';
    const toggle = u.blocked
      ? '<button class="btn btn--row btn--icon btn--row-unblock" data-action="unblock"' + dataAttr +
        ' title="Включить" aria-label="Включить">' + ICONS.unblock + "</button>"
      : '<button class="btn btn--row btn--icon btn--row-block" data-action="block"' + dataAttr +
        ' title="Отключить" aria-label="Отключить">' + ICONS.block + "</button>";
    const reissue = '<button class="btn btn--row btn--icon btn--row-reissue" data-action="reissue"' + dataAttr +
      ' title="Перевыпустить" aria-label="Перевыпустить">' + ICONS.reissue + "</button>";
    const del = '<button class="btn btn--row btn--icon btn--row-delete" data-action="delete"' + dataAttr +
      ' title="Удалить" aria-label="Удалить">' + ICONS.delete + "</button>";
    return '<div class="row-actions">' + toggle + reissue + del + "</div>";
  }

  function buildRow(u) {
    const tr = document.createElement("tr");
    tr.dataset.ip = u.ip;
    tr.innerHTML =
      '<td class="col-num"></td>' +
      "<td></td>" +
      '<td class="ip-cell"></td>' +
      '<td class="endpoint-cell"></td>' +
      '<td class="traffic-cell"></td>' +
      "<td></td>" +
      "<td></td>" +
      '<td class="col-action"></td>';
    const c = tr.children;
    const entry = {
      tr,
      cNum: c[0], cName: c[1], cIp: c[2], cEndpoint: c[3],
      cTraffic: c[4], cHs: c[5], cStatus: c[6], cAction: c[7],
    };
    entry.cIp.textContent = u.ip; // IP статичен (это ключ строки)
    updateRow(entry, u, true);
    return entry;
  }

  function updateRow(e, u, init) {
    if (init || e.vNum !== u.num) {
      e.cNum.textContent = u.num;
      e.vNum = u.num;
    }
    if (init || e.vName !== u.name) {
      e.cName.textContent = u.name;
      e.cName.className = u.name === "—" ? "name-cell name-cell--empty" : "name-cell";
      e.vName = u.name;
    }
    if (init || e.vEndpoint !== u.endpoint) {
      e.cEndpoint.textContent = u.endpoint;
      e.vEndpoint = u.endpoint;
    }
    const tStr = humanizeBytes(u.trafficBytes);
    if (init || e.vTraffic !== tStr) {
      e.cTraffic.textContent = tStr;
      e.vTraffic = tStr;
    }
    if (init || e.vHs !== u.handshake || e.vNeverSeen !== u.neverSeen) {
      e.cHs.textContent = u.handshake;
      e.cHs.className = u.neverSeen ? "hs-cell hs-cell--never" : "hs-cell";
      e.vHs = u.handshake;
      e.vNeverSeen = u.neverSeen;
    }
    // Статус и кнопки перестраиваем только при смене признака блокировки —
    // тяжёлую часть (иконки) не трогаем каждую секунду.
    if (init || e.vBlocked !== u.blocked) {
      e.cStatus.innerHTML = statusPillHtml(u);
      e.cAction.innerHTML = actionCellHtml(u);
      e.vBlocked = u.blocked;
      e.vRecentlyActive = u.recentlyActive;
    } else if (!u.blocked && e.vRecentlyActive !== u.recentlyActive) {
      // только индикатор "онлайн" (пульс) — тоггл класса без перестройки
      const dot = e.cStatus.querySelector(".status-dot--active");
      if (dot) dot.classList.toggle("status-dot--live", u.recentlyActive);
      e.vRecentlyActive = u.recentlyActive;
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
      if (state.statusFilter === "online" && !u.recentlyActive) return false;
      if (state.statusFilter === "blocked" && !u.blocked) return false;
      if (!q) return true;
      return u.name.toLowerCase().includes(q) || u.ip.toLowerCase().includes(q);
    });

    const tbody = els.tableBody;

    if (filtered.length === 0) {
      rowEls.clear();
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Никого не найдено</td></tr>';
      return;
    }

    // убрать плейсхолдер ("Загрузка…"/"Никого не найдено") — у него нет data-ip
    const ph = tbody.querySelector("tr:not([data-ip])");
    if (ph) ph.remove();

    // реконсиляция по ключу-IP: существующие строки обновляем на месте,
    // новые вставляем в нужную позицию, исчезнувшие удаляем
    const desired = new Set();
    let prev = null;
    for (const u of filtered) {
      desired.add(u.ip);
      let entry = rowEls.get(u.ip);
      if (!entry) {
        entry = buildRow(u);
        rowEls.set(u.ip, entry);
      } else {
        updateRow(entry, u, false);
      }
      const ref = prev ? prev.nextSibling : tbody.firstChild;
      if (ref !== entry.tr) tbody.insertBefore(entry.tr, ref);
      prev = entry.tr;
    }
    for (const [ip, entry] of rowEls) {
      if (!desired.has(ip)) {
        entry.tr.remove();
        rowEls.delete(ip);
      }
    }
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
      // локально отражаем статус сразу; полный список подтянется ближайшим тиком
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
      loadUsers();
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
  els.searchInput.addEventListener("input", (e) => {
    state.search = e.target.value;
    render();
  });
  els.includeNeverToggle.addEventListener("change", (e) => {
    state.includeNever = e.target.checked;
    loadUsers(); // строки "не подключавшихся" плавно добавятся/уберутся реконсиляцией
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) loadUsers();
  });

  // первичная загрузка + автообновление раз в секунду (когда вкладка активна)
  loadUsers();
  setInterval(() => {
    if (!document.hidden) loadUsers();
  }, REFRESH_MS);
})();
