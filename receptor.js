const crypto = require('crypto');
const fs = require('fs');

// RETO 3: Manejo de excepciones y control de errores
const usarClaveIncorrecta = process.argv.includes('--wrong-key');

const archivoLlavePrivada = usarClaveIncorrecta
  ? 'gerson_privada.pem'
  : 'miguel_privada.pem';

// Cargar llaves requeridas
const llavePrivadaMiguel = fs.readFileSync(archivoLlavePrivada, 'utf8');
const llavePublicaGerson = fs.readFileSync('gerson_publica.pem', 'utf8');

const opcionesRSA = {
  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256'
};

// Leer paquete recibido
const paquete = JSON.parse(fs.readFileSync('paquete_transito.json', 'utf8'));

try {
  // DESCIFRADO del mensaje (Confidencialidad -> Su propia Clave PRIVADA)
  const bufferCifrado = Buffer.from(paquete.datosCifrados, 'base64');
  const bufferDescifrado = crypto.privateDecrypt(
    { key: llavePrivadaMiguel, ...opcionesRSA },
    bufferCifrado
  );
  const mensajeTextoPlano = bufferDescifrado.toString('utf8');
  console.log(`[✔] Mensaje descifrado exitosamente: "${mensajeTextoPlano}"`);

  // RETO 1: Descifrar la clave AES y luego el archivo adjunto
  const claveAESCifrada = Buffer.from(paquete.claveAESCifrada, 'base64');
  const claveAES = crypto.privateDecrypt(
    { key: llavePrivadaMiguel, ...opcionesRSA },
    claveAESCifrada
  );

  const iv = Buffer.from(paquete.iv, 'base64');
  const authTag = Buffer.from(paquete.authTag, 'base64');
  const archivoCifrado = Buffer.from(paquete.archivoCifrado, 'base64');

  const descifradorAES = crypto.createDecipheriv('aes-256-gcm', claveAES, iv);
  descifradorAES.setAuthTag(authTag);
  const archivoDescifrado = Buffer.concat([
    descifradorAES.update(archivoCifrado),
    descifradorAES.final()
  ]);

  const nombreSalida = `recuperado_${paquete.nombreArchivoOriginal}`;
  fs.writeFileSync(nombreSalida, archivoDescifrado);
  console.log(
    `[✔] Archivo adjunto recuperado intacto como "${nombreSalida}" (${archivoDescifrado.length} bytes).`
  );

  // VERIFICACIÓN DE FIRMA (Integridad -> Clave PÚBLICA del Emisor)
  const verificador = crypto.createVerify('SHA256');
  verificador.update(mensajeTextoPlano);
  verificador.update(archivoDescifrado);
  verificador.end();

  const esValido = verificador.verify(llavePublicaGerson, paquete.firma, 'base64');

  if (esValido) {
    console.log(
      '[✔] INTEGRIDAD CONFIRMADA: El mensaje y el archivo realmente provienen de Gerson y no fueron alterados.'
    );
  } else {
    console.log(
      '[X] ALERTA DE SEGURIDAD: La firma no coincide. El contenido fue alterado en tránsito (posible ataque MITM).'
    );
  }
} catch (error) {
  // RETO 3: captura elegante de la excepción, sin dejar tronar la consola
  const esFalloDeDescifrado =
    error.code === 'ERR_OSSL_RSA_OAEP_DECODING_ERROR' ||
    error.code === 'ERR_OSSL_RSA_DATA_TOO_LARGE_FOR_KEY_SIZE' ||
    /decrypt/i.test(error.message) ||
    /padding/i.test(error.message) ||
    /Unsupported state or unable to authenticate data/i.test(error.message);

  if (esFalloDeDescifrado) {
    console.error(
      `[X] FALLA DE CONFIDENCIALIDAD: No fue posible descifrar el paquete con la clave "${archivoLlavePrivada}". ` +
        'Esto ocurre si la clave privada no corresponde a la clave pública con la que se cifró el mensaje, ' +
        'o si los datos cifrados fueron alterados/corrompidos en tránsito (p. ej. por un ataque MITM sobre el texto cifrado).'
    );
  } else {
    console.error('[X] ERROR CRÍTICO al procesar el paquete:', error.message);
  }
}