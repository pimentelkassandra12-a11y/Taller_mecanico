const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
// Servir archivos estáticos desde la raíz del proyecto (CSS, imágenes, música, etc.)
app.use(express.static(path.join(__dirname)));

// Inicializar Firebase Admin (soporta env vars para Render + fallback a firebase_key.json)
let db = null;
const bcrypt = require('bcryptjs');
try {
  const admin = require('firebase-admin');

  let initialized = false;
  // 1) FIREBASE_SERVICE_ACCOUNT_B64: base64(JSON)
  if (process.env.FIREBASE_SERVICE_ACCOUNT_B64) {
    try {
      const jsonStr = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_B64, 'base64').toString('utf8');
      const serviceAccount = JSON.parse(jsonStr);
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      db = admin.firestore();
      initialized = true;
      console.log('Conexión a Firestore inicializada desde FIREBASE_SERVICE_ACCOUNT_B64');
    } catch (err) {
      console.warn('Fallo al parsear FIREBASE_SERVICE_ACCOUNT_B64:', err.message);
    }
  }

  // 2) FIREBASE_SERVICE_ACCOUNT: JSON string
  if (!initialized && process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const serviceAccount = typeof process.env.FIREBASE_SERVICE_ACCOUNT === 'string'
        ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
        : process.env.FIREBASE_SERVICE_ACCOUNT;
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      db = admin.firestore();
      initialized = true;
      console.log('Conexión a Firestore inicializada desde FIREBASE_SERVICE_ACCOUNT');
    } catch (err) {
      console.warn('Fallo al parsear FIREBASE_SERVICE_ACCOUNT:', err.message);
    }
  }

  // 3) Fallback a firebase_key.json en la raíz
  if (!initialized) {
    const serviceAccountPath = path.join(__dirname, 'firebase_key.json');
    if (fs.existsSync(serviceAccountPath)) {
      try {
        const serviceAccount = require(serviceAccountPath);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        db = admin.firestore();
        initialized = true;
        console.log('Conexión a Firestore inicializada desde firebase_key.json');
      } catch (err) {
        console.warn('Error al inicializar Firebase Admin con firebase_key.json:', err.message);
      }
    } else {
      console.warn('Advertencia: no se encontró firebase_key.json en la raíz del proyecto y no se proporcionaron credenciales por ENV. La API de usuarios no funcionará sin las credenciales.');
    }
  }
} catch (err) {
  console.warn('firebase-admin no está instalado o ocurrió un error al inicializar Firebase Admin:', err.message);
}

// API: registrar usuario (hash de contraseña)
app.post('/api/register', async (req, res) => {
  if (!db) return res.status(500).json({ ok: false, message: 'Base de datos no inicializada' });
  const { usuario, contra } = req.body || {};
  if (!usuario || !contra) return res.status(400).json({ ok: false, message: 'Faltan campos usuario o contra' });

  try {
    const usuariosRef = db.collection('usuarios');
    const q = await usuariosRef.where('usuario', '==', usuario).get();
    if (!q.empty) return res.status(409).json({ ok: false, message: 'El usuario ya existe' });

    const saltRounds = 10;
    const hashed = await bcrypt.hash(contra, saltRounds);

    const docRef = await usuariosRef.add({ usuario, contra: hashed });
    const newUser = { id: docRef.id, usuario };
    return res.json({ ok: true, user: newUser });
  } catch (err) {
    console.error('Error al registrar usuario:', err);
    return res.status(500).json({ ok: false, message: 'Error interno' });
  }
});

// API: login (compara hash o texto plano; migra automáticamente a bcrypt)
app.post('/api/login', async (req, res) => {
  if (!db) return res.status(500).json({ ok: false, message: 'Base de datos no inicializada' });
  const { usuario, contra } = req.body || {};
  if (!usuario || !contra) return res.status(400).json({ ok: false, message: 'Faltan campos usuario o contra' });

  try {
    const usuariosRef = db.collection('usuarios');
    const q = await usuariosRef.where('usuario', '==', usuario).limit(1).get();
    
    if (q.empty) return res.status(401).json({ ok: false, message: 'Credenciales incorrectas' });

    const doc = q.docs[0];
    const data = doc.data();
    const stored = data.contra;
    let match = false;

    // Detectar si está hasheado (bcrypt comienza con $2 y tiene ~60 caracteres)
    const isBcrypt = typeof stored === 'string' && stored.startsWith('$2') && stored.length >= 50;

    if (isBcrypt) {
      // Hash bcrypt: comparar directamente
      try {
        match = await bcrypt.compare(contra, stored);
      } catch (bcryptErr) {
        match = false;
      }
    } else {
      // Texto plano: comparar y migrar automáticamente
      match = (contra === stored);
      if (match) {
        try {
          const newHash = await bcrypt.hash(contra, 10);
          await usuariosRef.doc(doc.id).update({ contra: newHash });
        } catch (hashErr) {
          // Error al hashear, pero la sesión ya coincide, permitimos
        }
      }
    }

    if (!match) return res.status(401).json({ ok: false, message: 'Credenciales incorrectas' });

    const user = { id: doc.id, usuario: data.usuario };
    return res.json({ ok: true, user });
  } catch (err) {
    console.error('Error en login:', err);
    return res.status(500).json({ ok: false, message: 'Error interno' });
  }
});

// API: obtener usuarios (lista)
app.get('/api/users', async (req, res) => {
  if (!db) return res.status(500).json({ ok: false, message: 'Base de datos no inicializada' });
  try {
    const usuariosRef = db.collection('usuarios');
    const snapshot = await usuariosRef.get();
    const users = snapshot.docs.map(d => ({ id: d.id, ...d.data() }));
    return res.json({ ok: true, users });
  } catch (err) {
    console.error('Error al obtener usuarios:', err);
    return res.status(500).json({ ok: false, message: 'Error interno' });
  }
});

// Endpoint de debug para verificar inicialización de Firestore
app.get('/debug/db', (req, res) => {
  if (process.env.DEBUG_TOKEN) {
    const token = req.headers['x-debug-token'] || req.query.token;
    if (!token || token !== process.env.DEBUG_TOKEN) return res.status(403).json({ ok: false, message: 'Forbidden' });
  }
  const hasLocal = fs.existsSync(path.join(__dirname, 'firebase_key.json'));
  const source = process.env.FIREBASE_SERVICE_ACCOUNT_B64 ? 'env_b64' : (process.env.FIREBASE_SERVICE_ACCOUNT ? 'env_json' : (hasLocal ? 'local_file' : 'none'));
  return res.json({ ok: true, initialized: !!db, source });
});

// Rutas principales: servir los HTML desde la carpeta views
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get(['/index.html', '/inicio.html'], (req, res) => {
  const file = req.path === '/inicio.html' ? 'inicio.html' : 'index.html';
  res.sendFile(path.join(__dirname, 'views', file));
});

// Manejo simple de 404
app.use((req, res) => {
  res.status(404).send('404 - No encontrado');
});

app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
