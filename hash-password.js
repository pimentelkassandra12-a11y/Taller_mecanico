const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const fs = require('fs');

// Inicializar Firebase
const serviceAccount = JSON.parse(fs.readFileSync('./firebase_key.json', 'utf8'));
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

async function hashPassword() {
  try {
    // Hash "12345"
    const plainPassword = "12345";
    const hashedPassword = await bcrypt.hash(plainPassword, 10);
    console.log('Contraseña hasheada:', hashedPassword);

    // Actualizar en Firestore
    const userRef = db.collection('usuarios').doc('Y4TugNZanFB46jpJVOqL');
    await userRef.update({ contra: hashedPassword });
    console.log('Contraseña actualizada en Firestore');

    process.exit(0);
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
}

hashPassword();
