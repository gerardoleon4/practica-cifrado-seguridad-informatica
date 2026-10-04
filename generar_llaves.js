const crypto = require('crypto');
const fs = require('fs');

function generarParClaves(nombreUsuario) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048, // Tamaño seguro estándar
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  fs.writeFileSync(`${nombreUsuario}_publica.pem`, publicKey);
  fs.writeFileSync(`${nombreUsuario}_privada.pem`, privateKey);
  console.log(`[+] Par de llaves generado exitosamente para: ${nombreUsuario}`);
}

generarParClaves('gerson');
generarParClaves('miguel');
