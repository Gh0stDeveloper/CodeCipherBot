# Seguridad

## Reportes

No publiques tokens, contraseñas, archivos privados ni pruebas de concepto
activas en un issue público. Contacta al mantenedor por
[`@Gh0stDeveloper`](https://t.me/Gh0stDeveloper) y describe el impacto, la
versión afectada y pasos mínimos para reproducirlo.

## Modelo de amenazas

- El bot considera no confiable todo texto, documento y ZIP recibido.
- Los decodificadores no importan, evalúan ni ejecutan cargas.
- Los ZIP rechazan rutas absolutas, `..`, symlinks, exceso de entradas y exceso
  de tamaño descomprimido.
- El cifrado real usa AEAD; una contraseña errónea o contenido modificado se
  rechaza antes de devolver datos.
- Las contraseñas solo viven en la sesión RAM de un intento y el bot intenta
  borrar el mensaje de Telegram.
- SQLite almacena metadatos, no el contenido ni contraseñas.
- El rol administrativo se calcula en servidor usando `OWNER_IDS` y
  `ADMIN_IDS`.

## Límites del diseño

Un wrapper autoejecutable contiene la información necesaria para recuperar su
carga. Es ofuscación, no confidencialidad. El operador del runtime siempre puede
inspeccionar el código recuperado. Para secretos usa un contenedor `.gcb` y
entrega la contraseña por un canal separado.

Telegram conserva mensajes y documentos según sus propias políticas. Si el
material es altamente sensible, no debe enviarse a un bot de terceros.

