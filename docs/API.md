# API del panel

Todas las respuestas son JSON. Las rutas administrativas requieren
`Authorization: Bearer <token>`. El CORS solo acepta orígenes definidos en
`CORS_ORIGINS` o el origen de `PANEL_URL`.

| Método y ruta | Acceso | Descripción |
| --- | --- | --- |
| `GET /health` | público | Salud del proceso |
| `GET /api/public/status` | público | Estado, límites y métodos |
| `POST /api/auth/telegram` | público | Valida `{ "init_data": "..." }` |
| `POST /api/auth/code` | público | Consume `{ "code": "..." }` |
| `GET /api/me` | sesión | Perfil, historial y presets |
| `DELETE /api/me/history` | sesión | Borra historial propio |
| `GET /api/admin/stats` | admin | Estadísticas |
| `GET /api/admin/users` | admin | Usuarios paginados |
| `PUT /api/admin/users/:id/ban` | admin | `{ "banned": true|false }` |
| `PUT /api/admin/methods/:key` | admin | `{ "enabled": true|false }` |
| `PUT /api/admin/maintenance` | admin | Estado y mensaje público |
| `POST /api/admin/broadcast` | admin | Difusión de hasta 3500 caracteres |
| `GET /api/admin/logs` | admin | Auditoría reciente |

Las sesiones del panel duran una hora. `initData` debe tener menos de quince
minutos. Los códigos de `/panel` duran cinco minutos y se invalidan al usarse.

