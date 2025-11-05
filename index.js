const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
// Simple request logger
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});
// Servir `inicio.html` en la raíz para que Render o el enlace público abra esa página primero
app.get('/', (req, res) => {
  const inicioPath = path.join(__dirname, 'views', 'inicio.html');
  console.log(`[ROUTE] GET / -> sirviendo ${inicioPath}`);
  return res.sendFile(inicioPath);
});

// Servir archivos estáticos desde la raíz del proyecto (CSS, imágenes, música, etc.)
app.use(express.static(path.join(__dirname)));

// Inicializar Firebase Admin usando la llave local `firebase_key.json`
let db = null;
const bcrypt = require('bcryptjs');
try {
  const admin = require('firebase-admin');
  const serviceAccountPath = path.join(__dirname, 'firebase_key.json');

  // 1) Preferir variable de entorno FIREBASE_SERVICE_ACCOUNT (JSON string)
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
      admin.initializeApp({ credential: admin.credential.cert(sa) });
      db = admin.firestore();
      console.log('[FIREBASE] Inicializado desde variable de entorno FIREBASE_SERVICE_ACCOUNT');
    } catch (err) {
      console.error('[FIREBASE] Error parseando FIREBASE_SERVICE_ACCOUNT:', err && err.message);
    }
  }

  // 2) Fallback a archivo local firebase_key.json (útil en desarrollo local)
  if (!db && fs.existsSync(serviceAccountPath)) {
    try {
      const serviceAccount = require(serviceAccountPath);
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      db = admin.firestore();
      console.log('[FIREBASE] Inicializado desde firebase_key.json (archivo local)');
    } catch (err) {
      console.error('[FIREBASE] Error al inicializar desde archivo:', err && err.message);
    }
  }

  // 3) Si no se pudo inicializar, emitir advertencia con instrucciones para Render
  if (!db) {
    console.warn('[FIREBASE] No se inicializó Firestore. Añade la variable de entorno FIREBASE_SERVICE_ACCOUNT con el JSON de la cuenta de servicio o sube firebase_key.json en la raíz para desarrollo local.');
  } else {
    console.log('Conexión a Firestore inicializada.');
    // Log ping to Firestore to verify connectivity
    db.listCollections().then(cols => {
      console.log(`[FIRESTORE] Conectado, colecciones encontradas: ${cols.map(c=>c.id).slice(0,5).join(', ')}`);
    }).catch(err => {
      console.error('[FIRESTORE] Error al listar colecciones (conexión parcial):', err && err.message);
    });
  }
} catch (err) {
  console.warn('firebase-admin no está instalado o ocurrió un error al inicializar Firebase Admin:', err && err.message);
}

// API: registrar usuario (hash de contraseña)
app.post('/api/register', async (req, res) => {
  if (!db) {
    console.error('[REGISTER] Intento de registro pero la base de datos no está inicializada');
    return res.status(500).json({ ok: false, message: 'Base de datos no inicializada' });
  }
  const { usuario, contra } = req.body || {};
  if (!usuario || !contra) return res.status(400).json({ ok: false, message: 'Faltan campos usuario o contra' });

  try {
    console.log(`[REGISTER] Nuevo intento de registro para usuario='${usuario}'`);
    const usuariosRef = db.collection('usuarios');
    const q = await usuariosRef.where('usuario', '==', usuario).get();
    if (!q.empty) return res.status(409).json({ ok: false, message: 'El usuario ya existe' });

    const saltRounds = 10;
    const hashed = await bcrypt.hash(contra, saltRounds);
    console.log(`[REGISTER] Contraseña hasheada (longitud ${hashed.length}) para usuario='${usuario}'`);

    const docRef = await usuariosRef.add({ usuario, contra: hashed });
    const newUser = { id: docRef.id, usuario };
    console.log(`[REGISTER] Usuario creado id=${docRef.id} usuario='${usuario}'`);
    return res.json({ ok: true, user: newUser });
  } catch (err) {
    console.error('[REGISTER] Error al registrar usuario:', err && err.message);
    return res.status(500).json({ ok: false, message: 'Error interno' });
  }
});

// API: login (compara hash)
app.post('/api/login', async (req, res) => {
  if (!db) {
    console.error('[LOGIN] Intento de login pero la base de datos no está inicializada');
    return res.status(500).json({ ok: false, message: 'Base de datos no inicializada' });
  }
  const { usuario, contra } = req.body || {};
  if (!usuario || !contra) return res.status(400).json({ ok: false, message: 'Faltan campos usuario o contra' });

  try {
    console.log(`[LOGIN] Intento de login para usuario='${usuario}'`);
    const usuariosRef = db.collection('usuarios');
    const q = await usuariosRef.where('usuario', '==', usuario).limit(1).get();
    console.log(`[LOGIN] Query a Firestore completada, docs encontrados: ${q.size}`);
    if (q.empty) {
      console.warn(`[LOGIN] Usuario no encontrado: '${usuario}'`);
      return res.status(401).json({ ok: false, message: 'Credenciales incorrectas', debug: 'user-not-found' });
    }

    const doc = q.docs[0];
    const data = doc.data();
    if (!data || !data.contra) {
      console.error(`[LOGIN] Documento inválido para id=${doc.id}:`, data);
      return res.status(500).json({ ok: false, message: 'Error interno', debug: 'invalid-doc' });
    }
    const stored = data.contra;
    console.log(`[LOGIN] Valor 'contra' obtenido (longitud ${stored ? stored.length : 0}) para id=${doc.id}`);

    let match = false;
    // Detectar si el valor almacenado parece un hash bcrypt (comienza con $2 y longitud típica)
    const looksLikeBcrypt = typeof stored === 'string' && stored.startsWith('$2') && stored.length >= 50;
    if (looksLikeBcrypt) {
      console.log('[LOGIN] Campo contra parece ser un hash bcrypt; usando bcrypt.compare');
      match = await bcrypt.compare(contra, stored);
    } else {
      console.log('[LOGIN] Campo contra NO parece estar hasheado; comparando texto plano (migración automática si coincide)');
      // comparación directa (solo para compatibilidad de datos antiguos)
      if (contra === stored) {
        match = true;
        try {
          // Re-hash la contraseña y actualiza el documento para migrarlo a bcrypt
          const newHash = await bcrypt.hash(contra, 10);
          await usuariosRef.doc(doc.id).update({ contra: newHash });
          console.log(`[LOGIN] Migración: contraseña en texto plano actualizada a hash para id=${doc.id}`);
        } catch (err) {
          console.error(`[LOGIN] Error al migrar contraseña a hash para id=${doc.id}:`, err && err.message);
        }
      }
    }

    console.log(`[LOGIN] Resultado de comparación de contraseñas para usuario='${usuario}': ${match}`);
    if (!match) {
      console.warn(`[LOGIN] Contraseña incorrecta para usuario='${usuario}'`);
      return res.status(401).json({ ok: false, message: 'Credenciales incorrectas', debug: 'wrong-password' });
    }

    const user = { id: doc.id, usuario: data.usuario };
    console.log(`[LOGIN] Autenticación exitosa para usuario='${usuario}', id=${doc.id}`);
    return res.json({ ok: true, user });
  } catch (err) {
    console.error('[LOGIN] Error en login:', err && err.message);
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

// Rutas principales: servir los HTML desde la carpeta views
// La raíz ya está configurada para servir 'views/inicio.html' más arriba.
// Añadimos una ruta limpia para el dashboard y mantenemos acceso a index/inicio si se piden explícitamente.
app.get('/dashboard', (req, res) => {
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
