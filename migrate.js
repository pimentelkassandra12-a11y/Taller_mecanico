const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const serviceAccount = require('./firebase_key.json');

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

(async () => {
  try {
    const hashed = await bcrypt.hash('12345', 10);
    console.log('Hash generado:', hashed);
    
    await db.collection('usuarios').doc('Y4TugNZanFB46jpJVOqL').update({ contra: hashed });
    console.log('Usuario actualizado en Firestore');
    process.exit(0);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
})();
