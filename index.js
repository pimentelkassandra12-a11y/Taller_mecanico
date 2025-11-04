const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Servir archivos estáticos desde la raíz del proyecto (CSS, imágenes, música, etc.)
app.use(express.static(path.join(__dirname)));

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
