"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Method = {
  key: string;
  label: string;
  category: string;
  enabled: boolean;
};

type PublicStatus = {
  name: string;
  version: string;
  online: boolean;
  maintenance: boolean;
  maintenance_message?: string;
  users: number;
  operations_today: number;
  methods: Method[];
  limits: {
    max_file_mb: number;
    rate_per_minute: number;
  };
};

type User = {
  id: number;
  username?: string;
  first_name?: string;
  role: "user" | "admin" | "owner";
  banned?: boolean;
  operations?: number;
  last_seen?: string;
};

type Operation = {
  id: number;
  method: string;
  filename?: string;
  status: string;
  created_at: string;
};

type AdminStats = {
  total_users: number;
  active_today: number;
  total_operations: number;
  operations_today: number;
  failed_operations: number;
  popular_methods: Array<{ method: string; count: number }>;
};

type AuditLog = {
  id: number;
  actor_id: number;
  action: string;
  target?: string;
  created_at: string;
};

declare global {
  interface Window {
    Telegram?: {
      WebApp?: {
        initData?: string;
        ready: () => void;
        expand: () => void;
        colorScheme?: "light" | "dark";
      };
    };
  }
}

const demoStatus: PublicStatus = {
  name: "CodeCipherBot",
  version: "2.0.0",
  online: false,
  maintenance: false,
  users: 0,
  operations_today: 0,
  limits: { max_file_mb: 10, rate_per_minute: 20 },
  methods: [
    { key: "runnable_auto", label: "Protección ejecutable automática", category: "Código", enabled: true },
    { key: "runnable_node", label: "Node.js ejecutable", category: "Código", enabled: true },
    { key: "aes_gcm_encrypt", label: "AES-256-GCM", category: "Cifrado", enabled: true },
    { key: "chacha20_encrypt", label: "ChaCha20-Poly1305", category: "Cifrado", enabled: true },
    { key: "base64_encode", label: "Base64 · Codificar", category: "Codificación", enabled: true },
  ],
};

const navItems = [
  ["overview", "Resumen"],
  ["methods", "Métodos"],
  ["activity", "Actividad"],
  ["users", "Usuarios"],
  ["control", "Control"],
] as const;

function formatDate(value?: string) {
  if (!value) return "Sin actividad";
  return new Intl.DateTimeFormat("es-MX", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export default function Home() {
  const [active, setActive] = useState<(typeof navItems)[number][0]>("overview");
  const [apiUrl, setApiUrl] = useState("");
  const [draftApiUrl, setDraftApiUrl] = useState("");
  const [status, setStatus] = useState<PublicStatus>(demoStatus);
  const [token, setToken] = useState("");
  const [me, setMe] = useState<User | null>(null);
  const [history, setHistory] = useState<Operation[]>([]);
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loginCode, setLoginCode] = useState("");
  const [broadcast, setBroadcast] = useState("");
  const [maintenanceMessage, setMaintenanceMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("Configura la URL pública del backend para conectar datos reales.");
  const [showConnection, setShowConnection] = useState(false);

  const isAdmin = me?.role === "admin" || me?.role === "owner";
  const connected = status.online && Boolean(apiUrl);

  const apiRequest = useCallback(
    async <T,>(path: string, options: RequestInit = {}): Promise<T> => {
      if (!apiUrl) throw new Error("Falta la URL del backend");
      const headers = new Headers(options.headers);
      headers.set("Content-Type", "application/json");
      if (token) headers.set("Authorization", `Bearer ${token}`);
      const response = await fetch(`${apiUrl}${path}`, {
        ...options,
        headers,
        credentials: "omit",
      });
      const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        throw new Error(String(payload.error ?? `Error HTTP ${response.status}`));
      }
      return payload as T;
    },
    [apiUrl, token],
  );

  const loadStatus = useCallback(
    async (target = apiUrl) => {
      if (!target) return;
      setLoading(true);
      try {
        const response = await fetch(`${target}/api/public/status`);
        if (!response.ok) throw new Error("El backend no respondió correctamente");
        const payload = (await response.json()) as PublicStatus;
        setStatus(payload);
        setNotice("Conexión segura establecida con el backend.");
        setShowConnection(false);
      } catch (error) {
        setStatus({ ...demoStatus, online: false });
        setNotice(error instanceof Error ? error.message : "No se pudo conectar");
      } finally {
        setLoading(false);
      }
    },
    [apiUrl],
  );

  const authenticate = useCallback(
    async (code?: string) => {
      if (!apiUrl) return;
      const initData = window.Telegram?.WebApp?.initData;
      if (!code && !initData) return;
      try {
        const path = code ? "/api/auth/code" : "/api/auth/telegram";
        const payload = await fetch(`${apiUrl}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(code ? { code } : { init_data: initData }),
        }).then(async (response) => {
          const result = await response.json();
          if (!response.ok) throw new Error(result.error ?? "No se pudo autenticar");
          return result as { token: string; user: User };
        });
        setToken(payload.token);
        setMe(payload.user);
        setNotice(`Sesión iniciada como ${payload.user.first_name || payload.user.username || payload.user.id}.`);
        if (code) {
          history.replaceState(null, "", location.pathname + location.search);
        }
      } catch (error) {
        setNotice(error instanceof Error ? error.message : "Autenticación rechazada");
      }
    },
    [apiUrl],
  );

  useEffect(() => {
    window.Telegram?.WebApp?.ready();
    window.Telegram?.WebApp?.expand();
    const bundled = process.env.NEXT_PUBLIC_API_URL ?? "";
    const saved = localStorage.getItem("codecipher_api_url") ?? "";
    const query = new URLSearchParams(location.search).get("api") ?? "";
    const initial = (query || saved || bundled).replace(/\/+$/, "");
    const code = new URLSearchParams(location.hash.slice(1)).get("code") ?? "";
    setDraftApiUrl(initial);
    setLoginCode(code);
    if (initial) setApiUrl(initial);
    else setShowConnection(true);
  }, []);

  useEffect(() => {
    if (!apiUrl) return;
    void loadStatus(apiUrl).then(() => authenticate(loginCode || undefined));
  }, [apiUrl, authenticate, loadStatus, loginCode]);

  useEffect(() => {
    if (!token) return;
    void apiRequest<{ user: User; history: Operation[] }>("/api/me")
      .then((payload) => {
        setMe(payload.user);
        setHistory(payload.history);
      })
      .catch((error) => setNotice(error.message));
  }, [apiRequest, token]);

  useEffect(() => {
    if (!isAdmin || !token) return;
    void Promise.all([
      apiRequest<AdminStats>("/api/admin/stats"),
      apiRequest<{ users: User[] }>("/api/admin/users?limit=50"),
      apiRequest<{ logs: AuditLog[] }>("/api/admin/logs"),
    ])
      .then(([statsPayload, usersPayload, logsPayload]) => {
        setStats(statsPayload);
        setUsers(usersPayload.users);
        setLogs(logsPayload.logs);
      })
      .catch((error) => setNotice(error.message));
  }, [apiRequest, isAdmin, token]);

  const enabledCount = useMemo(
    () => status.methods.filter((method) => method.enabled).length,
    [status.methods],
  );

  function saveConnection(event: FormEvent) {
    event.preventDefault();
    const normalized = draftApiUrl.trim().replace(/\/+$/, "");
    if (!/^https?:\/\//i.test(normalized)) {
      setNotice("Escribe una URL completa que comience con https://");
      return;
    }
    localStorage.setItem("codecipher_api_url", normalized);
    setApiUrl(normalized);
  }

  async function useCode(event: FormEvent) {
    event.preventDefault();
    await authenticate(loginCode.trim());
  }

  async function toggleMethod(method: Method) {
    if (!isAdmin) return;
    try {
      await apiRequest(`/api/admin/methods/${encodeURIComponent(method.key)}`, {
        method: "PUT",
        body: JSON.stringify({ enabled: !method.enabled }),
      });
      setStatus((current) => ({
        ...current,
        methods: current.methods.map((item) =>
          item.key === method.key ? { ...item, enabled: !item.enabled } : item,
        ),
      }));
      setNotice(`${method.label}: ${method.enabled ? "desactivado" : "activado"}.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "No se pudo actualizar");
    }
  }

  async function toggleMaintenance() {
    if (!isAdmin) return;
    try {
      const next = !status.maintenance;
      await apiRequest("/api/admin/maintenance", {
        method: "PUT",
        body: JSON.stringify({ enabled: next, message: maintenanceMessage.trim() }),
      });
      setStatus((current) => ({ ...current, maintenance: next }));
      setNotice(next ? "Modo mantenimiento activado." : "Servicio público reactivado.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "No se pudo actualizar");
    }
  }

  async function toggleBan(user: User) {
    if (!isAdmin || user.role !== "user") return;
    try {
      const banned = !user.banned;
      await apiRequest(`/api/admin/users/${user.id}/ban`, {
        method: "PUT",
        body: JSON.stringify({ banned }),
      });
      setUsers((current) =>
        current.map((item) => (item.id === user.id ? { ...item, banned } : item)),
      );
      setNotice(`${user.first_name || user.username || user.id}: ${banned ? "bloqueado" : "reactivado"}.`);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "No se pudo actualizar");
    }
  }

  async function sendBroadcast(event: FormEvent) {
    event.preventDefault();
    if (!broadcast.trim()) return;
    try {
      await apiRequest("/api/admin/broadcast", {
        method: "POST",
        body: JSON.stringify({ message: broadcast.trim() }),
      });
      setBroadcast("");
      setNotice("Difusión añadida a la cola.");
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "No se pudo enviar");
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">C</span>
          <div>
            <strong>CodeCipher</strong>
            <span>Control Center</span>
          </div>
        </div>

        <nav aria-label="Navegación principal">
          {navItems.map(([key, label]) => {
            if ((key === "users" || key === "control") && !isAdmin) return null;
            return (
              <button
                key={key}
                className={active === key ? "nav-item active" : "nav-item"}
                onClick={() => setActive(key)}
              >
                <span className="nav-dot" />
                {label}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <span className={connected ? "status-light online" : "status-light"} />
          <div>
            <strong>{connected ? "Backend conectado" : "Configuración pendiente"}</strong>
            <button onClick={() => setShowConnection(true)}>Cambiar conexión</button>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Sistema público de protección de código</p>
            <h1>{navItems.find(([key]) => key === active)?.[1]}</h1>
          </div>
          <div className="top-actions">
            <span className={status.maintenance ? "mode-pill warning" : "mode-pill"}>
              {status.maintenance ? "Mantenimiento" : "Operativo"}
            </span>
            <button className="profile-button" onClick={() => setShowConnection(true)}>
              <span>{me?.first_name?.slice(0, 1).toUpperCase() || "G"}</span>
              <div>
                <strong>{me?.first_name || me?.username || "Invitado"}</strong>
                <small>{me?.role || "vista pública"}</small>
              </div>
            </button>
          </div>
        </header>

        <div className="notice-bar" role="status">
          <span />
          {notice}
        </div>

        {active === "overview" && (
          <div className="dashboard-grid">
            <section className="hero-card">
              <div className="hero-copy">
                <p className="eyebrow">CodeCipherBot {status.version}</p>
                <h2>Código protegido. Ejecución intacta.</h2>
                <p>
                  Ofuscación ejecutable para lenguajes interpretados y cifrado autenticado
                  para archivos privados, administrado desde una sola superficie.
                </p>
                <div className="hero-actions">
                  <a href="https://t.me/CodeCipherBot" target="_blank" rel="noreferrer">
                    Abrir bot
                  </a>
                  <button onClick={() => setActive("methods")}>Ver métodos</button>
                </div>
              </div>
              <div className="code-orbit" aria-hidden="true">
                <span className="orbit-core">CC</span>
                <span className="orbit-tag tag-one">PY</span>
                <span className="orbit-tag tag-two">JS</span>
                <span className="orbit-tag tag-three">PHP</span>
                <span className="orbit-tag tag-four">SH</span>
              </div>
            </section>

            <section className="metric-row">
              <article>
                <span>Usuarios</span>
                <strong>{status.users.toLocaleString("es-MX")}</strong>
                <small>Acceso público</small>
              </article>
              <article>
                <span>Operaciones hoy</span>
                <strong>{status.operations_today.toLocaleString("es-MX")}</strong>
                <small>Sin almacenar archivos</small>
              </article>
              <article>
                <span>Métodos activos</span>
                <strong>{enabledCount}</strong>
                <small>de {status.methods.length} registrados</small>
              </article>
              <article>
                <span>Límite por archivo</span>
                <strong>{status.limits.max_file_mb} MB</strong>
                <small>{status.limits.rate_per_minute} solicitudes/min</small>
              </article>
            </section>

            <section className="panel methods-preview">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">Disponibilidad</p>
                  <h3>Métodos principales</h3>
                </div>
                <button onClick={() => setActive("methods")}>Administrar</button>
              </div>
              <div className="method-list">
                {status.methods.slice(0, 6).map((method) => (
                  <div className="method-line" key={method.key}>
                    <span className="method-symbol">{method.label.slice(0, 2).toUpperCase()}</span>
                    <div>
                      <strong>{method.label}</strong>
                      <small>{method.category}</small>
                    </div>
                    <span className={method.enabled ? "state enabled" : "state"}>
                      {method.enabled ? "Activo" : "Pausado"}
                    </span>
                  </div>
                ))}
              </div>
            </section>

            <section className="panel security-panel">
              <p className="eyebrow">Modelo de seguridad</p>
              <h3>Dos niveles claramente separados</h3>
              <div className="security-level">
                <span>01</span>
                <div>
                  <strong>Protección ejecutable</strong>
                  <p>El runtime recupera el código en memoria y conserva su comportamiento.</p>
                </div>
              </div>
              <div className="security-level">
                <span>02</span>
                <div>
                  <strong>Cifrado autenticado</strong>
                  <p>AES-GCM o ChaCha20 con contraseña para confidencialidad real.</p>
                </div>
              </div>
            </section>
          </div>
        )}

        {active === "methods" && (
          <section className="panel full-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Registro modular</p>
                <h2>Métodos disponibles</h2>
              </div>
              <span>{enabledCount} activos</span>
            </div>
            <div className="method-table">
              {status.methods.map((method) => (
                <div className="method-row" key={method.key}>
                  <span className="method-symbol">{method.label.slice(0, 2).toUpperCase()}</span>
                  <div>
                    <strong>{method.label}</strong>
                    <small>{method.key}</small>
                  </div>
                  <span>{method.category}</span>
                  <button
                    className={method.enabled ? "toggle on" : "toggle"}
                    onClick={() => toggleMethod(method)}
                    disabled={!isAdmin}
                    aria-label={`${method.enabled ? "Desactivar" : "Activar"} ${method.label}`}
                  >
                    <span />
                  </button>
                </div>
              ))}
            </div>
          </section>
        )}

        {active === "activity" && (
          <section className="panel full-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Metadatos privados</p>
                <h2>Actividad reciente</h2>
              </div>
              <span>El contenido nunca se conserva</span>
            </div>
            {history.length ? (
              <div className="activity-list">
                {history.map((item) => (
                  <article key={item.id}>
                    <span className={item.status === "success" ? "activity-icon success" : "activity-icon"} />
                    <div>
                      <strong>{item.method}</strong>
                      <small>{item.filename || "Entrada de texto"}</small>
                    </div>
                    <time>{formatDate(item.created_at)}</time>
                  </article>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <strong>Inicia sesión desde Telegram</strong>
                <p>Tu historial reciente aparecerá aquí sin guardar el contenido procesado.</p>
              </div>
            )}
          </section>
        )}

        {active === "users" && isAdmin && (
          <section className="panel full-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Administración</p>
                <h2>Usuarios</h2>
              </div>
              <span>{stats?.total_users ?? users.length} registrados</span>
            </div>
            <div className="user-table">
              {users.map((user) => (
                <article key={user.id}>
                  <span className="avatar">{(user.first_name || user.username || "U").slice(0, 1)}</span>
                  <div>
                    <strong>{user.first_name || user.username || `Usuario ${user.id}`}</strong>
                    <small>{user.id}</small>
                  </div>
                  <span>{user.operations ?? 0} operaciones</span>
                  <time>{formatDate(user.last_seen)}</time>
                  <span className={user.banned ? "state blocked" : "state enabled"}>
                    {user.banned ? "Bloqueado" : "Activo"}
                  </span>
                  <button
                    className="user-action"
                    onClick={() => toggleBan(user)}
                    disabled={user.role !== "user"}
                  >
                    {user.banned ? "Reactivar" : "Bloquear"}
                  </button>
                </article>
              ))}
            </div>
          </section>
        )}

        {active === "control" && isAdmin && (
          <div className="control-grid">
            <section className="panel">
              <p className="eyebrow">Disponibilidad</p>
              <h2>Modo mantenimiento</h2>
              <p className="muted">Los administradores conservan acceso mientras el público recibe un aviso.</p>
              <label className="maintenance-field">
                Mensaje público opcional
                <input
                  value={maintenanceMessage}
                  onChange={(event) => setMaintenanceMessage(event.target.value)}
                  placeholder="Estamos aplicando una actualización"
                  maxLength={500}
                />
              </label>
              <button className={status.maintenance ? "danger-button" : "primary-button"} onClick={toggleMaintenance}>
                {status.maintenance ? "Desactivar mantenimiento" : "Activar mantenimiento"}
              </button>
            </section>
            <section className="panel">
              <p className="eyebrow">Comunicación</p>
              <h2>Difusión pública</h2>
              <form onSubmit={sendBroadcast} className="stack-form">
                <textarea
                  value={broadcast}
                  onChange={(event) => setBroadcast(event.target.value)}
                  placeholder="Escribe un aviso para todos los usuarios"
                  maxLength={3500}
                />
                <button className="primary-button" type="submit">Añadir a la cola</button>
              </form>
            </section>
            <section className="panel stats-card">
              <p className="eyebrow">Últimas 24 horas</p>
              <h2>Salud operativa</h2>
              <dl>
                <div><dt>Usuarios activos</dt><dd>{stats?.active_today ?? 0}</dd></div>
                <div><dt>Operaciones</dt><dd>{stats?.operations_today ?? 0}</dd></div>
                <div><dt>Fallos</dt><dd>{stats?.failed_operations ?? 0}</dd></div>
              </dl>
            </section>
            <section className="panel audit-card">
              <p className="eyebrow">Trazabilidad</p>
              <h2>Auditoría reciente</h2>
              <div className="audit-list">
                {logs.slice(0, 8).map((item) => (
                  <article key={item.id}>
                    <div>
                      <strong>{item.action}</strong>
                      <small>{item.target || `actor ${item.actor_id}`}</small>
                    </div>
                    <time>{formatDate(item.created_at)}</time>
                  </article>
                ))}
                {!logs.length && <p className="muted">Todavía no hay eventos administrativos.</p>}
              </div>
            </section>
          </div>
        )}
      </section>

      {showConnection && (
        <div className="modal-backdrop" role="presentation">
          <section className="connection-modal" role="dialog" aria-modal="true" aria-labelledby="connection-title">
            <button className="close-button" onClick={() => setShowConnection(false)} aria-label="Cerrar">×</button>
            <p className="eyebrow">Conexión segura</p>
            <h2 id="connection-title">Vincular backend</h2>
            <p>
              Escribe la URL HTTPS del bot desplegado. Se guarda únicamente como preferencia en este dispositivo.
            </p>
            <form onSubmit={saveConnection} className="stack-form">
              <label>
                URL del backend
                <input
                  value={draftApiUrl}
                  onChange={(event) => setDraftApiUrl(event.target.value)}
                  placeholder="https://api.tudominio.com"
                  inputMode="url"
                />
              </label>
              <button className="primary-button" type="submit" disabled={loading}>
                {loading ? "Conectando…" : "Guardar y conectar"}
              </button>
            </form>
            {!me && (
              <form onSubmit={useCode} className="stack-form code-form">
                <label>
                  Código administrativo de un solo uso
                  <input
                    value={loginCode}
                    onChange={(event) => setLoginCode(event.target.value)}
                    placeholder="Generado con /panel"
                  />
                </label>
                <button type="submit" className="secondary-button">Iniciar sesión</button>
              </form>
            )}
          </section>
        </div>
      )}
    </main>
  );
}
