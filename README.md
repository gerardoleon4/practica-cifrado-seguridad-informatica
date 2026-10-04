# Práctica 2 — Criptografía Asimétrica y Protección de Datos

Esquema de comunicación segura entre dos entidades usando **RSA en Node.js** (módulo nativo `crypto`, sin dependencias externas). **Gerson** (emisor) envía a **Miguel** (receptor) un mensaje confidencial y un archivo adjunto, cifrados y firmados digitalmente. Además se simula un ataque *Man-in-the-Middle* y se manejan los errores de descifrado.

## Objetivo

Implementar un esquema de comunicación segura con criptografía asimétrica (RSA) para evaluar y garantizar los principios de **Confidencialidad** e **Integridad** de los datos en tránsito, simulando escenarios reales de transmisión y ataques de alteración de información.

## Estructura del proyecto

| Archivo | Descripción |
|---|---|
| `generar_llaves.js` | Genera los pares de llaves RSA de 2048 bits (formato PEM) para Gerson y Miguel. |
| `emisor.js` | Gerson cifra el mensaje y el archivo adjunto con la llave pública de Miguel y firma con su llave privada. |
| `receptor.js` | Miguel descifra con su llave privada y verifica la firma con la llave pública de Gerson. |
| `atacante.js` | Simula un ataque MITM que altera un carácter del paquete en tránsito. |
| `documento.pdf` | Archivo adjunto de prueba (Reto 1). |
| `paquete_transito.json` | Paquete cifrado y firmado que "viaja" del emisor al receptor. |
| `*_publica.pem` | Llaves públicas. |

> Las llaves privadas (`*_privada.pem`) **no se suben al repositorio** (ver `.gitignore`). Se generan localmente con `generar_llaves.js`.

## Requisitos

- Node.js 18 o superior (probado con Node.js v23)

## Ejecución

```bash
# 1. Generar los pares de llaves de Gerson y Miguel
node generar_llaves.js

# 2. Gerson cifra y firma el mensaje + documento.pdf
node emisor.js

# 3. Miguel descifra y verifica la firma
node receptor.js
```

Salida esperada:

```
[+] Paquete cifrado y firmado enviado correctamente a 'paquete_transito.json'
[i] Archivo adjunto "documento.pdf" (32 bytes) cifrado con AES-256-GCM; la clave AES viaja cifrada con RSA.

[✔] Mensaje descifrado exitosamente: "REPORTE CONFIDENCIAL: Se ha detectado una vulnerabilidad crítica en el servidor central."
[✔] Archivo adjunto recuperado intacto como "recuperado_documento.pdf" (32 bytes).
[✔] INTEGRIDAD CONFIRMADA: El mensaje y el archivo realmente provienen de Gerson y no fueron alterados.
```

## Retos

### Reto 1 — Cifrado de archivos adjuntos

RSA solo puede cifrar datos más pequeños que su llave (con 2048 bits y OAEP-SHA256, máximo 190 bytes), así que no sirve para cifrar archivos directamente. Por eso se usa **cifrado híbrido**:

1. Se genera una clave **AES-256** aleatoria y un IV.
2. `documento.pdf` se cifra con **AES-256-GCM**.
3. La clave AES se cifra con la **llave pública RSA de Miguel** (padding OAEP + SHA-256).
4. La firma digital cubre el mensaje **y** el contenido del archivo.

El receptor descifra la clave AES con su llave privada, recupera el archivo como `recuperado_documento.pdf` y este queda idéntico byte a byte al original.

```bash
node emisor.js && node receptor.js
cmp documento.pdf recuperado_documento.pdf && echo "Archivos idénticos"
```

### Reto 2 — Simulación de ataque Man-in-the-Middle

`atacante.js` intercepta `paquete_transito.json` y cambia **un solo carácter** antes de que llegue a Miguel.

**Alterando la firma** (opción por defecto):

```bash
node emisor.js
node atacante.js
node receptor.js
```

```
[!] Atacante interceptando 'paquete_transito.json'...
[!] Campo "firma" alterado: carácter en posición 10 cambiado de "n" a "C".
[!] Paquete modificado guardado. Miguel recibirá un paquete corrupto sin saberlo.

[✔] Mensaje descifrado exitosamente: "REPORTE CONFIDENCIAL: ..."
[✔] Archivo adjunto recuperado intacto como "recuperado_documento.pdf" (32 bytes).
[X] ALERTA DE SEGURIDAD: La firma no coincide. El contenido fue alterado en tránsito (posible ataque MITM).
```

**Alterando el texto cifrado:**

```bash
node emisor.js
node atacante.js --dato
node receptor.js
```

```
[!] Campo "datosCifrados" alterado: carácter en posición 10 cambiado de "8" a "W".
[X] FALLA DE CONFIDENCIALIDAD: No fue posible descifrar el paquete con la clave "miguel_privada.pem". ...
```

Con el padding OAEP, modificar el texto cifrado hace que el descifrado falle por completo, así que el atacante tampoco puede inyectar un mensaje distinto.

### Reto 3 — Manejo de excepciones y control de errores

`receptor.js` envuelve todo el proceso en `try/catch`. Si se intenta descifrar con una llave privada que no corresponde (por ejemplo, la de Gerson), el programa no truena: informa la falla de confidencialidad.

```bash
node emisor.js
node receptor.js --wrong-key
```

```
[X] FALLA DE CONFIDENCIALIDAD: No fue posible descifrar el paquete con la clave "gerson_privada.pem". Esto ocurre si la clave privada no corresponde a la clave pública con la que se cifró el mensaje, o si los datos cifrados fueron alterados/corrompidos en tránsito (p. ej. por un ataque MITM sobre el texto cifrado).
```

## Justificación técnica

### Confidencialidad

El mensaje se cifra con la **llave pública de Miguel**. En RSA, lo que cifra la llave pública solo puede descifrarlo su **llave privada** correspondiente, y obtener la llave privada a partir de la pública requiere factorizar un número de 2048 bits, algo computacionalmente inviable hoy en día. El Base64 que viaja en `paquete_transito.json` es solo una forma de representar bytes cifrados como texto: **no es cifrado** y no aporta información sobre el contenido. Por eso un tercero que lo intercepte solo ve datos sin sentido. Además, el padding **OAEP** agrega aleatoriedad: cifrar dos veces el mismo mensaje produce resultados distintos, lo que impide ataques por comparación.

### Integridad (firma digital)

Gerson calcula el hash **SHA-256** del mensaje y del archivo y lo firma con su **llave privada**. Miguel recalcula el hash del contenido recibido y comprueba la firma con la **llave pública de Gerson**:

- Si un atacante modifica el contenido, el hash cambia y ya no coincide con la firma.
- Si modifica la firma, esta deja de ser válida para ese hash.
- El atacante no puede generar una firma nueva válida porque no tiene la llave privada de Gerson.

Esto garantiza **integridad** (el contenido no fue alterado) y **autenticidad / no repudio** (solo Gerson pudo firmarlo).

### Disponibilidad (rendimiento)

El cifrado asimétrico es **mucho más lento** que el simétrico (del orden de cientos a miles de veces), porque usa exponenciación modular con números muy grandes, mientras que AES trabaja con operaciones simples sobre bloques y suele tener aceleración por hardware (AES-NI). Además, RSA solo cifra bloques pequeños (máximo 190 bytes en esta configuración).

Cifrar archivos grandes o mucho tráfico solo con RSA consumiría mucho CPU y afectaría la disponibilidad del servicio. Por eso en la práctica (TLS, PGP y en el Reto 1) se usa un **esquema híbrido**: RSA solo para intercambiar una clave simétrica pequeña y AES para cifrar los datos. Así se obtiene la seguridad del cifrado asimétrico con el rendimiento del simétrico.
