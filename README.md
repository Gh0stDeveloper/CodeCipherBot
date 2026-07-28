# CodeCipherBot 2

Bot público de Telegram para proteger código ejecutable, codificar, comprimir,
cifrar, firmar y analizar archivos. Incluye una API Flask, panel web/Mini App,
SQLite, límites de abuso y controles administrativos.

Panel desplegado:
[codecipherbot-control.gh0stdeveloper.chatgpt.site](https://codecipherbot-control.gh0stdeveloper.chatgpt.site)

## Acción obligatoria: rota el token

El token original apareció dentro del código y debe considerarse comprometido.
En `@BotFather`, ejecuta `/revoke`, genera otro token y guárdalo únicamente en
`BOT_TOKEN`. No reutilices ni publiques el token anterior.

## Protección ejecutable frente a cifrado

Son dos funciones distintas:

- **Protección ejecutable:** el resultado puede iniciarse directamente con su
  runtime. Como el cargador debe recuperar el código sin pedir una clave, es
  ofuscación reversible y no puede ocultarlo frente a un analista.
- **Cifrado real:** AES-256-GCM o ChaCha20-Poly1305 con contraseña, salt
  aleatorio, PBKDF2 y autenticación. Protege confidencialidad e integridad, pero
  primero debe descifrarse; no es autoejecutable.

El backend nunca ejecuta los scripts enviados. La recuperación de wrappers, la
detección y el análisis son estáticos.

## Compatibilidad ejecutable

| Entrada | Salida | Compatibilidad |
| --- | --- | --- |
| Python `.py` | `.py` Base64, Zlib, Emoji o multicapa | Mismo comportamiento normal del intérprete |
| Python `.py` Marshal | `.py` bytecode | Misma versión mayor/menor de Python |
| Node `.js`, `.cjs` | CommonJS autocargable | Conserva `require`, `exports`, `__filename` |
| JavaScript navegador `.js` | Script autocargable | Navegadores modernos con `TextDecoder` |
| HTML `.html` | Documento autocargable | Conserva rutas relativas habituales |
| PHP `.php` | `.php` autocargable | Requiere PHP con `base64_decode` |
| Bash `.sh` | `.sh` autocargable | GNU/Linux y macOS |
| PowerShell `.ps1` | `.ps1` autocargable | PowerShell 5+ / PowerShell Core |
| Ruby `.rb` | `.rb` autocargable | `Base64` de la biblioteca estándar |
| Perl `.pl` | `.pl` autocargable | `MIME::Base64` |
| Lua `.lua` | `.lua` autocargable | Lua con `load` o `loadstring` |

Java, Kotlin, Go, C, C++, C#, Rust, Swift, TypeScript y módulos Node ESM
necesitan compilación, transpilación o bundling. No existe un único archivo
portable para todos los sistemas sin conocer toolchain, plataforma y
arquitectura. El bot lo indica en vez de entregar un archivo que falle.

El modo `/batch protect` procesa proyectos ZIP sin cambiar rutas ni nombres:
protege scripts compatibles y copia recursos/configuración sin alterarlos. Los
paquetes Node con `"type": "module"` se omiten para no romper imports ESM.

## Funciones públicas

- `/start`, `/help`, `/cancel`, `/methods`
- `/protect`, `/encode`, `/decode`, `/encrypt`, `/decrypt`
- `/batch protect|unwrap`
- `/hash`, `/verifyhash`
- `/keygen`, `/sign`, `/verify` con Ed25519
- `/qr`, `/detect`, `/analyze`
- `/preset`, `/history`, `/settings`, `/language`
- `/limits`, `/status`, `/privacy`, `/about`, `/panel`

Todos los usuarios pueden usar estas funciones. `OWNER_IDS` y `ADMIN_IDS` solo
controlan acciones administrativas:

- `/admin`, `/stats`, `/users`, `/logs`, `/health`
- `/ban`, `/unban`, `/broadcast`
- `/maintenance`, `/enablemethod`, `/disablemethod`
- `/exportdata` (solo propietario)

El panel permite consultar actividad propia. Los administradores además pueden
ver estadísticas, usuarios y auditoría; bloquear cuentas; activar métodos;
iniciar mantenimiento y poner difusiones en cola.

## Instalación

Requiere Python 3.10 o posterior.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Exporta las variables de `.env` con tu gestor de secretos y ejecuta:

```bash
python main.py
```

En PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
$env:BOT_TOKEN = "TOKEN_NUEVO"
$env:OWNER_IDS = "TU_ID"
py main.py
```

En Termux:

```bash
pkg update
pkg install python
python -m pip install -r requirements.txt
export BOT_TOKEN="TOKEN_NUEVO"
export OWNER_IDS="TU_ID"
python main.py
```

## Configuración esencial

| Variable | Predeterminado | Uso |
| --- | --- | --- |
| `BOT_TOKEN` | obligatoria | Token nuevo de BotFather |
| `OWNER_IDS` | vacío | IDs con control total |
| `ADMIN_IDS` | vacío | IDs administrativos adicionales |
| `DATABASE_PATH` | `./data/codecipherbot.sqlite3` | SQLite de metadatos |
| `MAX_FILE_SIZE_MB` | `10` | Entrada individual, máximo 20 MB |
| `MAX_BATCH_FILES` | `40` | Entradas máximas por ZIP |
| `MAX_BATCH_UNCOMPRESSED_MB` | `30` | Salida descomprimida máxima |
| `RATE_LIMIT_PER_MINUTE` | `20` | Límite por usuario |
| `PANEL_URL` | vacío | URL del panel/Mini App |
| `PUBLIC_API_URL` | vacío | URL HTTPS que `/panel` entrega al frontend |
| `CORS_ORIGINS` | vacío | Orígenes exactos autorizados |
| `ADMIN_SESSION_SECRET` | derivada | Secreto independiente recomendado |
| `RUN_MODE` | `polling` | `polling` o `webhook` |

Consulta [`.env.example`](.env.example) para ver todas las variables.

### Panel y Mini App

1. Despliega este backend con HTTPS.
2. Define `PANEL_URL` y añade ese mismo origen a `CORS_ORIGINS`.
3. Abre el panel y configura la URL HTTPS del backend.
4. En BotFather, configura el dominio de la Mini App si deseas abrirla dentro
   de Telegram.
5. `/panel` usa `initData` de Telegram. Para administradores también genera un
   código alternativo de un solo uso que caduca a los cinco minutos.

La API valida la firma HMAC y la antigüedad de `initData`; el cliente nunca
decide su propio rol.

## Despliegue con Docker o Railway

```bash
docker build -t codecipherbot .
docker run --rm -p 8080:8080 --env-file .env codecipherbot
```

Railway usa `Dockerfile`, expone `/health` y ejecuta Telegram y la API en el
mismo proceso. Monta un volumen para `/app/data` si quieres conservar SQLite
entre despliegues. Para varias réplicas, migra metadatos a una base de datos
compartida antes de escalar.

En webhook configura también:

```text
RUN_MODE=webhook
WEBHOOK_BASE_URL=https://api.example.com
WEBHOOK_PATH_SECRET=valor-aleatorio
WEBHOOK_HEADER_SECRET=valor-aleatorio
```

## Pruebas

```bash
python -m pytest -q
python -m compileall -q .
```

La suite comprueba wrappers, ejecución real cuando el runtime está instalado,
ZIPs, cifrado autenticado, modificación de ciphertext, almacenamiento, API,
autenticación de Telegram y compatibilidad heredada.

## Estructura

```text
codecipher/
├── batch.py       # proyectos ZIP seguros
├── bot.py         # comandos públicos y administrativos
├── config.py      # entorno y límites
├── registry.py    # registro único de métodos
├── runnable.py    # wrappers y recuperación estática
├── security.py    # AES-GCM y ChaCha20-Poly1305
├── storage.py     # SQLite de metadatos
├── tools.py       # hashes, QR, firmas, análisis
└── web.py         # API del panel/Mini App
```

El código del panel se encuentra en `dashboard/`. La arquitectura y el contrato
HTTP están en [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) y
[`docs/API.md`](docs/API.md).
