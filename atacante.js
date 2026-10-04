const fs = require('fs');


// RETO 2: Simulación de ataque Man-in-the-Middle 
const objetivo = process.argv.includes('--dato') ? 'datosCifrados' : 'firma';

const paquete = JSON.parse(fs.readFileSync('paquete_transito.json', 'utf8'));

console.log("[!] Atacante interceptando 'paquete_transito.json'...");

const valorOriginal = paquete[objetivo];
const posicion = 10;
const caracterOriginal = valorOriginal[posicion];
// Cambiamos el carácter por otro válido en Base64, distinto al original
const alfabetoBase64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
let caracterNuevo = caracterOriginal;
while (caracterNuevo === caracterOriginal) {
  caracterNuevo = alfabetoBase64[Math.floor(Math.random() * alfabetoBase64.length)];
}

const valorAlterado =
  valorOriginal.substring(0, posicion) + caracterNuevo + valorOriginal.substring(posicion + 1);
paquete[objetivo] = valorAlterado;

fs.writeFileSync('paquete_transito.json', JSON.stringify(paquete, null, 2));

console.log(
  `[!] Campo "${objetivo}" alterado: carácter en posición ${posicion} cambiado de "${caracterOriginal}" a "${caracterNuevo}".`
);
console.log('[!] Paquete modificado guardado. Miguel recibirá un paquete corrupto sin saberlo.');
