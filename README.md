# Taller_mecanico

Pequeño servidor Express que sirve las páginas estáticas y expone una API mínima para usuarios usando Firestore.

Requisitos
- Node.js (v14+ recomendada)
- Una cuenta de Firebase con Firestore y una llave de servicio (archivo `firebase_key.json`) colocada en la raíz del proyecto.

Instalación
```powershell
npm install
```

Variables/archivos sensibles
- No subas `firebase_key.json` al repositorio. El proyecto ya incluye `.gitignore` con esa entrada.

Ejecutar
```powershell
npm start
# o
node index.js
```
- Abre `http://localhost:3000/` para ver la interfaz.

Endpoints de API
- POST /api/register  -> { usuario, contra }  (registra usuario, guarda contraseña hasheada)
- POST /api/login     -> { usuario, contra }  (autentica y devuelve datos del usuario sin la contraseña)
- GET  /api/users     -> lista de usuarios (id y usuario)

Notas de seguridad
- Las contraseñas se guardan hasheadas usando bcryptjs. Para producción, usa HTTPS y políticas adicionales.
- Protege `firebase_key.json` y no la publiques.

Sugerencias
- Añadir validaciones más estrictas en el cliente y servidor.
- Implementar sesiones seguras o JWT para proteger rutas privadas.
- No versionar `node_modules`.
