require('dotenv').config(); // Asegúrate de que dotenv esté al inicio
const { Pool } = require('pg'); // Importa Pool desde pg

// Render proporciona la URL de conexión completa en una variable de entorno
// que configuraremos más adelante en el dashboard de Render.
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.error("Error: La variable de entorno DATABASE_URL no está definida.");
  console.error("Asegúrate de configurarla en Render con la 'Internal Connection String' de tu base de datos PostgreSQL.");
  process.exit(1); // Detiene la aplicación si no hay URL de BD
}

const pool = new Pool({
  connectionString: connectionString,
  // Render generalmente requiere SSL para conexiones externas,
  // pero para conexiones internas (entre servicios de Render) puede que no.
  // Si tienes problemas de conexión SSL, puedes probar añadiendo:
  // ssl: {
  //   rejectUnauthorized: false // ¡OJO! Menos seguro, usar solo si es necesario y entiendes las implicaciones.
  // }
});

// Prueba la conexión (opcional pero recomendado)
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error al adquirir cliente de la base de datos', err.stack);
  }
  console.log('Conectado exitosamente a la base de datos PostgreSQL en Render.');
  client.query('SELECT NOW()', (err, result) => {
    release(); // Libera el cliente de vuelta al pool
    if (err) {
      return console.error('Error ejecutando query de prueba', err.stack);
    }
    console.log('Query de prueba ejecutada:', result.rows);
  });
});

module.exports = pool; // Exporta el pool configurado para pg