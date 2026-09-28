# AudioScribe Local

[Descargar instaladores](https://github.com/adrian-afergon/AudioScribe/releases) · [Tests y builds](https://github.com/adrian-afergon/AudioScribe/actions)

Aplicación local para detectar nuevos MP3/MP4, transcribir en español y separar hablantes. Cola SQLite persistente, recuperación por bloques y resultados Markdown. Primera versión: destilado manual; la integración automática con tu second brain se aborda en una segunda fase.


## Accesos y arranque (0.3.0)

En el asistente, abre la pestaña **Accesos y arranque** antes de instalar:

| Plataforma | Escritorio opcional | Lista de aplicaciones opcional | Anclado guiado |
|---|---|---|---|
| Windows | Acceso `.lnk` | Menú Inicio | Inicio o barra de tareas |
| Linux | Lanzador `.desktop` | Menú de aplicaciones | Favoritos o panel, según escritorio |
| macOS | Acceso a `AudioScribe.app` | `~/Applications` | Dock |

Las opciones de escritorio y ayuda para anclar empiezan desmarcadas; la lista de aplicaciones está seleccionada. La ayuda para anclar activa también la lista de aplicaciones. Al terminar se muestran los pasos: el anclado lo completa la persona en su sistema. En Linux puede ser necesario permitir iniciar el lanzador; algunos escritorios no muestran iconos.

El arranque al iniciar sesión tiene su propia casilla, independiente de los accesos. Las elecciones se guardan en `launcher-options.json` junto a la configuración. Desmarcar una opción no elimina accesos existentes. Puedes cambiar las opciones desde **Configurar**; si el servicio está activo, detenlo antes de guardar la configuración.

Referencias: [Windows Inicio](https://learn.microsoft.com/en-us/windows/configuration/start/layout), [Dock de macOS](https://support.apple.com/guide/mac-help/desktop-menu-bar-and-dock-mchlws12345m2/mac), [lanzadores Linux](https://specifications.freedesktop.org/desktop-entry/latest-single/).


## Instalar en Windows

1. Ejecuta `AudioScribe-Setup.exe`.
2. Selecciona instalación, entrada, salida, second brain existente y datos/modelos.
3. Elige modelo y procesador. `small` con CPU es el punto de partida; `medium` o `large-v3` requieren más recursos. CUDA necesita una GPU NVIDIA y sus bibliotecas compatibles. macOS funciona por CPU en esta versión.
4. Abre el enlace a [las condiciones de pyannote Community-1](https://huggingface.co/pyannote/speaker-diarization-community-1), acéptalas con tu cuenta de Hugging Face y crea un token de lectura autorizado para ese modelo. Introdúcelo en el asistente. No es una clave OpenAI y no se guarda.
5. Pulsa **Instalar y configurar**. El instalador descarga un Python privado, dependencias y modelos. No necesitas instalar Python por separado. Reserva al menos 10 GB libres; el tamaño final varía por plataforma y modelo.
6. Tras cargar y verificar los modelos, se activa el inicio de sesión, comienza el servicio y se abre el panel **AudioScribe**. En el menú Inicio tendrás **AudioScribe**, **Configurar**, **Iniciar**, **Detener** y **Estado** (también abre el panel).

## Panel de actividad y pausa

El panel muestra si el servicio está activo, detenido, procesando, en pausa o sin señal reciente. Se actualiza cada segundo, con contadores de pendientes, activos, completados y errores. La tabla muestra hasta 300 trabajos; selecciona uno para ver su ruta, intentos, mensaje de error y resultado. Puedes abrir su Markdown, reintentar un error, abrir el registro o la carpeta de resultados.

**Pausar** solicita una pausa cooperativa: el panel muestra primero «Pausa solicitada» y después «En pausa» cuando el motor llega a un punto seguro. Puede tardar durante una carga de modelo o una operación de inferencia. No se pierde el bloque en curso y el modelo permanece en memoria. La vigilancia de la carpeta continúa y los nuevos audios quedan en cola. **Reanudar** continúa el trabajo. La pausa se conserva si reinicias la aplicación.

**Detener** cierra el servicio y conserva los bloques completados; al volver a iniciarlo se repite, si es necesario, el bloque que estaba en curso. También funciona mientras el servicio está pausado. Cerrar la ventana del panel no detiene el servicio.

El porcentaje es del texto transcrito, no una estimación de tiempo total. La separación de hablantes muestra su etapa y sus contadores. El estado del servicio se comprueba mediante señal periódica y bloqueo del sistema operativo, no solo por una fila antigua de SQLite.

## Actualizar una instalación existente

Ejecuta el instalador 0.3.0 en la misma ubicación. Detecta la configuración de la ubicación predeterminada, conserva las rutas y reutiliza los modelos descargados. Si elegiste otra ubicación, selecciónala y utiliza las mismas rutas guardadas en su `config.toml`. El instalador solicita una parada segura antes de sustituir el paquete y abre el panel al terminar. No es necesario volver a descargar modelos ni introducir el token si ya están preparados.

La primera instalación necesita Internet y puede tardar varios minutos. El progreso detallado está en `installation.log`, dentro de la instalación. Si falla la descarga, repite el asistente con las mismas rutas: se reutilizan los archivos descargados. Si pospones los modelos, la configuración queda guardada, pero el servicio no se activa todavía.

La aplicación no sube audios. La diarización utiliza exclusivamente el modelo local Community-1; no se utiliza el servicio alojado de pyannoteAI. Se desactiva su telemetría. La API de OpenAI no forma parte de esta versión.

## Qué se considera nuevo

Al guardar por primera vez la configuración de una carpeta, los audios existentes se registran como excluidos. Los que entren después, incluso con la aplicación cerrada, se incorporan a la cola. También se detectan archivos modificados como nuevas versiones. Las subcarpetas solo se incluyen si se seleccionan.

Un archivo debe mantener tamaño y fecha estables durante 30 segundos antes de encolarse. Esto reduce las lecturas de copias incompletas, pero no puede demostrar que una transferencia pausada haya terminado: para transferencias controladas, copia con extensión temporal y renombra a `.mp3` o `.mp4` al terminar. Los archivos corruptos registran el error y se reintentan con espera creciente.

Los duplicados exactos se reconocen mediante SHA-256. Renombrar el audio no provoca otra transcripción si ya existe un resultado válido con el mismo perfil. El audio original nunca se borra ni se mueve. Los archivos ocultos temporales de la aplicación no se procesan.

## Resultados y estados

Los Markdown aparecen en `SALIDA/raw/transcripciones/`. Incluyen fuente, huella, idioma, modelo y texto con etiquetas de hablantes, sin marcas de tiempo. Las etiquetas son locales a cada grabación: no identifican personas por nombre ni reconocen al mismo hablante entre audios.

SQLite guarda `pending`, `processing`, `done` y `error`, además de intentos, progreso y ruta de salida. Los archivos preexistentes se registran aparte como excluidos. Los resultados se publican mediante renombrado atómico y se verifican por huella. Si editas un resultado, la aplicación lo conserva y señala la modificación al reiniciar; `reprocess` genera una versión nueva.

Se guarda progreso cada 10 minutos de transcripción, con contexto solapado de 2 segundos. Una interrupción repite como máximo el bloque en curso. La diarización se calcula sobre el audio completo para mantener etiquetas coherentes: si se interrumpe esa etapa, se vuelve a ejecutar completa, pero se reutiliza el texto ya transcrito. La separación de voces superpuestas no reconstruye palabras que Whisper haya omitido.

## Configuración y manejo

Para cambiar opciones, usa **Detener**, espera a que se libere el servicio y abre **Configurar**. Las rutas se almacenan en `config.toml`. El directorio de datos permanece fijo al reconfigurar para conservar la cola; una migración de datos debe hacerse con el servicio detenido.

También hay CLI. En Windows, `PYTHON` es `INSTALACIÓN/environment/Scripts/python.exe`; en Linux/macOS, `INSTALACIÓN/environment/bin/python`:

```text
PYTHON -m audioscribe --config CONFIG status
PYTHON -m audioscribe --config CONFIG panel
PYTHON -m audioscribe --config CONFIG pause
PYTHON -m audioscribe --config CONFIG resume
PYTHON -m audioscribe --config CONFIG stop
PYTHON -m audioscribe --config CONFIG setup
PYTHON -m audioscribe --config CONFIG run
PYTHON -m audioscribe --config CONFIG retry 12
PYTHON -m audioscribe --config CONFIG reprocess RUTA_AUDIO.mp4
PYTHON -m audioscribe --config CONFIG disable-autostart
```

`reprocess` permite incluir explícitamente audios que ya estaban presentes al instalar. SQLite reside en `DATOS/queue.sqlite3`; los registros rotan en `DATOS/audioscribe.log`. Cada ordenador tiene una instalación y una base local independientes; no compartir el mismo SQLite entre ordenadores ni sincronizarlo mientras está abierto.

El asistente comprueba las rutas sin escribir en el second brain. No se inspeccionan ni modifican sus notas. [Prompt para destilado manual](docs/DESTILAR.md).

## Linux y macOS

Se incluyen archivos `.tar.gz` de instalación para Linux y macOS, en x86_64 y ARM64. Extrae el archivo correspondiente y ejecuta `Instalar.sh` (Linux) o `Instalar.command` (macOS). Se prepara un Python privado para mostrar el mismo asistente de rutas; no hace falta Python preinstalado. El asistente necesita una sesión gráfica.

El código incluye arranque por `systemd --user` y `launchd`, respectivamente. Los paquetes bootstrap se ensamblan sin ejecutar la instalación de cada plataforma; requieren validación de instalación en sus sistemas de destino. Linux requiere una distribución con `systemd` para el inicio automático; otros sistemas pueden ejecutar la CLI manualmente. No se consideran validados por haber probado Windows.

Los paquetes generados no están firmados ni notarizados. Esta versión no incluye actualizador automático. Reejecutar un instalador actualizado, con el servicio detenido, conserva la configuración y SQLite. Para desactivar la aplicación basta con `disable-autostart` y `stop`; no borres el directorio de datos si quieres conservar el historial.

## Desarrollo y construcción

Python 3.11. Crear un entorno virtual e instalar:

```text
python -m pip install -e ".[test]" build pyinstaller uv
python -m pytest -q
python installer/build.py --output dist
python installer/build_portable.py --output dist/unix
```

La compilación incluye un gestor `uv` y el paquete de la aplicación. El instalador descarga dependencias pesadas en un entorno aislado. La acción `.github/workflows/packages.yml` ejecuta tests en Windows, Linux y macOS y construye cinco instaladores en cada push a `main`, pull request o ejecución manual. Solo los pushes de tags `vX.Y.Z` publican releases, después de superar los tests y todas las builds. Las ejecuciones manuales nunca publican una release, aunque se elija un tag. Los paquetes Unix son archivos bootstrap ensamblados en Linux; los tests no validan la instalación gráfica completa en cada plataforma.

Con dependencias de compilación ya instaladas, `build.py --offline` evita descargas. `build_portable.py --offline` reutiliza los binarios de uv de los archivos de salida existentes.

Para pruebas reales del motor: `python -m pip install -e ".[engine]"`. Las pruebas unitarias no descargan modelos ni sustituyen la validación humana de calidad. Los módulos se separan en configuración, SQLite, vigilancia, motor, arranque y asistente.

## Referencias y licencias de dependencias

- [faster-whisper](https://github.com/SYSTRAN/faster-whisper): MIT.
- [pyannote.audio](https://github.com/pyannote/pyannote-audio): MIT.
- [Community-1](https://huggingface.co/pyannote/speaker-diarization-community-1): CC-BY-4.0 y condiciones de acceso indicadas por el proveedor.
- [uv](https://github.com/astral-sh/uv): MIT o Apache-2.0.
- [PyInstaller](https://pyinstaller.org/en/stable/license.html): licencia y excepción para los ejecutables generados.

Consulta las licencias completas de cada dependencia antes de redistribuir una versión comercial.

## Clonar y publicar una versión

```sh
git clone https://github.com/adrian-afergon/AudioScribe.git
cd AudioScribe
python -m venv .venv
# Activa .venv según tu sistema.
python -m pip install -e ".[test]"
python -m pytest -q
```

Para una nueva versión, cambia `version` en `pyproject.toml` y `__version__` en `src/audioscribe/__init__.py`, actualiza la documentación y confirma los cambios. Ambos valores deben coincidir con el tag; se admiten versiones estables `X.Y.Z`. Después:

```sh
git push origin main
git tag -a v0.3.0 -m "AudioScribe 0.3.0"
git push origin v0.3.0
```

Sustituye `0.3.0` por la versión que vayas a publicar. No reutilices ni muevas tags publicados. No necesitas secretos adicionales: Actions utiliza `GITHUB_TOKEN`, con escritura solo en el job de release. Se prepara un borrador, se suben los cinco instaladores y `SHA256SUMS.txt`, y se publica únicamente al terminar. Una ejecución fallida no publica una release incompleta; un reintento puede completar su borrador. Una release ya publicada no se sobrescribe.

Los instaladores llevan la versión en el nombre. GitHub también ofrece el código fuente del tag en ZIP y tar.gz. Las builds de ramas y PR quedan como artefactos de Actions durante 14 días. No se incluyen grabaciones, transcripciones, modelos ni configuraciones personales en Git.
