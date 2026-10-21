# Historias Clínicas

App web para las historias clínicas del consultorio: fichas de pacientes, evoluciones, estudios complementarios,
búsqueda, impresión a PDF e importación de las historias en Word (.docx).

**Este repositorio contiene solo el programa. Nunca se suben datos de pacientes acá.**

## Cómo funciona

- Los datos se guardan en **un archivo cifrado** (`historias.hc`) en tu Dropbox, en la carpeta configurada
  (por defecto `/historias clínicas`). El cifrado es AES-256-GCM con una clave derivada de tu contraseña
  (PBKDF2-SHA256, 600.000 iteraciones). Dropbox, GitHub o cualquiera que obtenga el archivo ve solo texto ilegible.
- **Backup:** cada día que hay cambios se guarda además una copia en `/historias clínicas/copias/historias-AAAA-MM-DD.hc`,
  y Dropbox conserva el historial de versiones de cada archivo. Desde *Ajustes* se puede bajar una copia cifrada a la computadora.
- **Archivos adjuntos** (PDF y fotos de estudios, epicrisis, informes): cada uno se guarda cifrado aparte en
  `/historias clínicas/adjuntos/`. Usan una clave propia guardada dentro de los datos cifrados, así cambiar la contraseña
  no obliga a recifrarlos. Las fotos grandes se achican a 2400 px (JPEG) antes de subirlas.
- La contraseña no se guarda en ningún lado. **Si se pierde, los datos no se pueden recuperar.**
- La app se bloquea sola tras 15 minutos sin uso (configurable en `config.js`).
- En el celular se abre la misma dirección; si no hay conexión muestra la última copia guardada, solo para leer.

## Puesta en marcha (una sola vez)

1. Entrá a <https://www.dropbox.com/developers/apps> → **Create app**.
   - *Scoped access* → *Full Dropbox* → un nombre único (por ejemplo `HC Consultorio Maldonado`).
2. En la pestaña **Permissions** marcá `files.content.read` y `files.content.write` y apretá **Submit**.
3. En la pestaña **Settings**:
   - En *OAuth 2 → Redirect URIs* agregá la dirección donde se publica la app
     (por ejemplo `https://drsebastianmaldonado.github.io/Historias-clinicas/`).
   - Copiá la **App key** y pegala en `config.js` (`dropboxAppKey`). La App key no es secreta.
4. Abrí la app, tocá **Conectar con Dropbox**, autorizá y creá la contraseña.
5. En el celular: abrí la misma dirección, conectá Dropbox, ingresá la contraseña y agregala a la pantalla de inicio.

## Importar las historias de Word

*Ajustes → Importar historias de Word*: se eligen todos los `.docx` juntos. El nombre del archivo (por ejemplo `245.docx`)
pasa a ser el N° de historia. Cada renglón que es solo una fecha (como `25/4/2014` o `19/5`) abre una evolución nueva;
«MC:», «Impresión diagnóstica:» y «Conducta:» van a su campo. El Word completo queda además en «Historia original completa». Se intentan reconocer
nombre, fecha de nacimiento y obra social (con o sin etiquetas como «Nombre:», «FN:», «OS:»); lo que no se reconozca se completa a mano.
Lee `.docx`, los `.doc` antiguos (Word 97-2003) y los `.odt` de LibreOffice/OpenOffice; de `.doc` y `.odt` se importa solo el texto, sin negritas.

## Probar sin Dropbox

En la primera pantalla, **Usar en modo prueba** guarda todo solo en ese navegador (sin backup). Es para probar con datos inventados.

## Desarrollo

Es HTML/CSS/JS sin compilación. Para probar en la computadora: `python3 -m http.server` y abrir `http://localhost:8000`.
`vendor/mammoth.browser.min.js` es [mammoth 1.11.0](https://github.com/mwilliamson/mammoth.js) (licencia BSD-2, ver `vendor/mammoth-LICENSE.txt`).
`vendor/jspdf.umd.min.js` es [jsPDF 2.5.2](https://github.com/parallax/jsPDF) (licencia MIT, ver `vendor/jspdf-LICENSE.txt`), para el PDF de cada evolución; se carga solo al usarlo.
`vendor/lector-doc.min.js` empaqueta [word-extractor 1.0.4](https://github.com/morungos/node-word-extractor) (licencia MIT, ver `vendor/word-extractor-LICENSE.txt`) para leer los `.doc`.
