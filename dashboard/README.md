# CodeCipherBot Control

Panel responsive y Telegram Mini App para la API de CodeCipherBot.

```bash
npm ci
npm run dev
```

La URL del backend se puede compilar con `NEXT_PUBLIC_API_URL` o guardar desde
el diálogo de conexión. El panel no guarda tokens en `localStorage`: las
sesiones solo permanecen en memoria y expiran en el backend.

La autenticación normal usa `Telegram.WebApp.initData`. Los administradores
también pueden abrir el enlace de un solo uso generado por `/panel`.

