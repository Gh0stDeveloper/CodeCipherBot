# CodeCipherBot

Bot de Telegram para codificar y decodificar texto o scripts, además de cifrar
archivos con contraseña. Está construido con `pyTelegramBotAPI` y
`pycryptodome`, sin base de datos y sin ejecutar archivos recibidos.

## Aviso urgente sobre el token

El token que estaba escrito dentro del `main.py` original fue publicado. Debes
considerarlo comprometido:

1. Abre `@BotFather` en Telegram.
2. Ejecuta `/revoke` y selecciona el bot.
3. Genera un token nuevo.
4. Guarda el token nuevo únicamente en `BOT_TOKEN`.

No vuelvas a incluir el token en el código, un ZIP, GitHub o una captura.

## Funciones

- Python:
  - Base64.
  - Base64 + Zlib.
  - Codificación Emoji.
  - Marshal.
  - Ofuscación multicapa Base85 + Zlib.
- JavaScript: Base64 con soporte UTF-8.
- PHP: Base64.
- Texto: Base64 UTF-8.
- Archivos: AES-256-GCM, PBKDF2-HMAC-SHA256, salt y nonce aleatorios.
- Menús editables y botón para volver.
- Sesiones separadas por chat y usuario.
- Contraseñas temporales de un solo intento.
- Límite de archivo y límite de solicitudes configurables.
- Lista opcional de usuarios autorizados.
- Procesamiento en memoria, sin nombres temporales compartidos.

## Correcciones de seguridad importantes

Los decodificadores antiguos cambiaban `exec` por `print` y después iniciaban el
archivo mediante `subprocess`. Un archivo preparado podía ejecutar comandos aun
sin usar literalmente `exec`. Esta versión solo extrae y valida cargas mediante
análisis estático.

El AES antiguo utilizaba ECB, una contraseña fija, relleno con espacios y un
formato de cifrado distinto al esperado por el descifrador. Se reemplazó por un
contenedor binario autenticado `.gcb`. Los archivos producidos por el método AES
antiguo no son compatibles porque aquel flujo estaba internamente roto.

Base64, Zlib, Emoji, Marshal y multicapa son ofuscación/codificación reversible;
no protegen un script contra alguien que quiera leerlo. Para confidencialidad
real utiliza la categoría **Cifrado seguro**.

## Instalación general

Requiere Python 3.10 o posterior.

```bash
python -m pip install -r requirements.txt
```

Configura el token y ejecuta:

```bash
export BOT_TOKEN="TOKEN_NUEVO"
python main.py
```

## Termux

```bash
pkg update
pkg install python
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
export BOT_TOKEN="TOKEN_NUEVO"
python main.py
```

Para mantenerlo activo durante una sesión puedes usar `termux-wake-lock` y
`tmux`. Android todavía puede cerrar Termux si tiene optimización de batería.

## Windows

PowerShell:

```powershell
py -m pip install -r requirements.txt
$env:BOT_TOKEN = "TOKEN_NUEVO"
py main.py
```

Símbolo del sistema:

```bat
py -m pip install -r requirements.txt
set BOT_TOKEN=TOKEN_NUEVO
py main.py
```

## Railway

1. Sube la carpeta a un repositorio privado.
2. Crea un proyecto desde ese repositorio.
3. En **Variables**, añade `BOT_TOKEN` con el token nuevo.
4. Railway usará el `Dockerfile` y ejecutará `python main.py`.

El proceso es un worker: no necesita exponer un puerto HTTP.

## VPS Ubuntu o Linux

Instala las dependencias dentro de un entorno virtual:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
export BOT_TOKEN="TOKEN_NUEVO"
python main.py
```

Para producción, guarda `BOT_TOKEN` en un archivo de entorno protegido y crea
un servicio `systemd`; no escribas el secreto directamente en el archivo
versionado.

## Variables

| Variable | Valor inicial | Descripción |
| --- | ---: | --- |
| `BOT_TOKEN` | obligatoria | Token nuevo de BotFather |
| `MAX_FILE_SIZE_MB` | `5` | Límite de entrada, entre 1 y 20 MB |
| `RATE_LIMIT_PER_MINUTE` | `12` | Operaciones por usuario cada minuto |
| `BOT_WORKERS` | `4` | Hilos para atender actualizaciones |
| `ALLOWED_USER_IDS` | vacío | IDs permitidos separados por comas |
| `LOG_LEVEL` | `INFO` | Nivel de registro |

Si `ALLOWED_USER_IDS` está vacío, cualquier usuario podrá usar el bot.

## Pruebas

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

Las pruebas verifican todos los ciclos de codificación, Unicode, autenticación
AES, contraseña incorrecta, modificación del ciphertext y que los
decodificadores no ejecuten el contenido recibido.

## Estructura

```text
CodeCipherBot/
├── main.py
├── config.py
├── encryption_methods.py
├── encrypt_methodos.py
├── requirements.txt
├── Dockerfile
├── Procfile
├── railway.toml
├── .env.example
└── tests/
```
