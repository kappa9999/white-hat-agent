# Correlacionar un límite de confianza móvil

Contexto: usar únicamente una compilación y un dispositivo de prueba identificados por hash y versión.

1. Registrar el identificador exacto de la aplicación, la compilación, el sistema y el dispositivo.
2. Localizar estáticamente una función que transforme datos externos antes de una decisión de autorización.
3. Añadir una observación mínima que capture argumentos, retorno, llamador y marca de tiempo sin modificar el valor.
4. Repetir una interacción normal y correlacionar la traza con la solicitud y la respuesta del servidor.
5. Separar lo que cambia solo en la interfaz de lo que el servidor acepta o conserva.
6. Documentar una hipótesis falsable con el efecto previsto, el experimento y una condición que la refute.
7. Retirar la observación, restaurar el estado inicial y verificar otra vez la identidad de la compilación.

Señal de éxito: una traza reproducible conecta la entrada externa, la función observada y la decisión real, sin
confundir un cambio local con autoridad del servidor.

Señal de fallo: la instrumentación desestabiliza la aplicación, la compilación cambia, la traza no se puede
correlacionar o el supuesto efecto proviene de otra ruta.
