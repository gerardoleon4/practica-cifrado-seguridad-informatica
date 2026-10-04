const crypto = require('crypto');
const fs = require('fs');

// Cargar llaves requeridas
const llavePublicaMiguel = fs.readFileSync('miguel_publica.pem', 'utf8');
const llavePrivadaGerson = fs.readFileSync('gerson_privada.pem', 'utf8');

const mensajeOriginal =
  'REPORTE CONFIDENCIAL: Se ha detectado una vulnerabilidad crítica en el servidor central.';

// Opciones de padding OAEP para cifrar y descifrar
const opcionesRSA = {
  padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  oaepHash: 'sha256'
};

// RETO 1: Cifrado de archivo adjunto con AES (RSA no puede cifrar archivos grandes directamente)
const rutaArchivo = 'documento.pdf';
const bufferArchivo = fs.readFileSync(rutaArchivo);

const claveAES = crypto.randomBytes(32); // 256 bits
const iv = crypto.randomBytes(16);
const cifradorAES = crypto.createCipheriv('aes-256-gcm', claveAES, iv);
const archivoCifrado = Buffer.concat([
  cifradorAES.update(bufferArchivo),
  cifradorAES.final()
]);
const authTag = cifradorAES.getAuthTag();

// Cifrar la clave AES con la clave pública de Miguel (RSA)
const claveAESCifrada = crypto.publicEncrypt(
  { key: llavePublicaMiguel, ...opcionesRSA },
  claveAES
);

// CIFRADO del mensaje (Confidencialidad -> Clave PÚBLICA del Destinatario)
const bufferMensaje = Buffer.from(mensajeOriginal, 'utf8');
const mensajeCifrado = crypto.publicEncrypt(
  { key: llavePublicaMiguel, ...opcionesRSA },
  bufferMensaje
);

// FIRMA DIGITAL (Integridad -> Clave PRIVADA del Emisor)
const firmador = crypto.createSign('SHA256');
firmador.update(mensajeOriginal);
firmador.update(bufferArchivo);
firmador.end();
const firmaDigital = firmador.sign(llavePrivadaGerson, 'base64');

// Guardar paquete cifrado simulando envío
const paqueteSeguro = {
  datosCifrados: mensajeCifrado.toString('base64'),
  archivoCifrado: archivoCifrado.toString('base64'),
  claveAESCifrada: claveAESCifrada.toString('base64'),
  iv: iv.toString('base64'),
  authTag: authTag.toString('base64'),
  nombreArchivoOriginal: rutaArchivo,
  firma: firmaDigital
};

fs.writeFileSync('paquete_transito.json', JSON.stringify(paqueteSeguro, null, 2));
console.log("[+] Paquete cifrado y firmado enviado correctamente a 'paquete_transito.json'");
console.log(
  `[i] Archivo adjunto "${rutaArchivo}" (${bufferArchivo.length} bytes) cifrado con AES-256-GCM; la clave AES viaja cifrada con RSA.`
);