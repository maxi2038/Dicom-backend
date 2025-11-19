require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const pool = require('./db'); // Este ahora usa 'pg' gracias a la modificación de db.js
const bcrypt = require('bcryptjs');
// Importa node-fetch (asegúrate de haberlo instalado con: npm install node-fetch@2)
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

// --- Configuración de Almacenamiento Multer ---
// Render provee un disco efímero, './uploads' funcionará temporalmente.
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');
// Asegurarse de que el directorio exista al iniciar (puede que no sea necesario en Render si se crea bajo demanda)
try {
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    console.log(`Directorio de subidas creado en: ${UPLOAD_DIR}`);
  }
} catch (err) {
  console.error("Error al crear el directorio de subidas:", err);
  // Considera si quieres detener la app aquí o manejarlo de otra forma
}

// Configura dónde servir los archivos estáticos subidos
app.use('/uploads', express.static(UPLOAD_DIR)); // Servir desde la ruta configurada

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const patientId = req.params.id;
    // Usa UPLOAD_DIR como base para las subidas
    const dir = path.join(UPLOAD_DIR, String(patientId));
    // Intenta crear el directorio específico del paciente
    fs.mkdir(dir, { recursive: true }, (err) => {
        if (err) {
            console.error("Error creando directorio para paciente:", dir, err);
            return cb(err); // Devuelve error si no se puede crear
        }
        cb(null, dir); // Directorio listo
    });
  },
  filename: (req, file, cb) => {
    // Genera un nombre de archivo seguro y único
    const safeOriginalName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'); // Limpia caracteres especiales
    const safeName = Date.now() + '_' + safeOriginalName;
    cb(null, safeName);
  }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // Ejemplo: Limita a 10MB por archivo
});

// --- Endpoints API ---

// Lista de pacientes
app.get('/api/patients', async (req, res) => {
  try {
    // pg usa 'rows' directamente del resultado
    const result = await pool.query(
      `SELECT "idPaciente" AS id, nombre, sexo, "rutaImagen", "nombreImagen", "fechaIngreso"
       FROM pacientes ORDER BY nombre` // Nombres de columnas en minúsculas o entre comillas si son camelCase en PG
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching patients:', err);
    res.status(500).json({ error: 'DB error retrieving patients' });
  }
});

// Endpoint de Autenticación (Login)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Faltan credenciales.' });
    }

    try {
        // Usa marcadores $1, $2... para PostgreSQL
        // Asegúrate que los nombres de tablas y columnas coincidan (sensible a mayúsculas/minúsculas en PG si se crearon con comillas)
        const result = await pool.query(
            `SELECT u.id, u.username, u.name, u.password, r."nombreRol", u."id_Rol"
             FROM users u
             JOIN roles r ON u."id_Rol" = r."idRol"
             WHERE u.username = $1`,
            [username]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });
        }

        const userResponse = {
            id: user.id,
            username: user.username,
            name: user.name,
            role: user.nombreRol, // Asegúrate que nombreRol esté en minúscula o entre comillas
            id_Rol: user.id_Rol,  // Asegúrate que id_Rol esté en minúscula o entre comillas
        };

        res.json({ success: true, user: userResponse });

    } catch (error) {
        console.error('Error en el endpoint /api/login:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor.' });
    }
});

// Estudios de un paciente
app.get('/api/patients/:id/studies', async (req, res) => {
  try {
    const pid = req.params.id;
    // Usa $1 y la función EXTRACT para PostgreSQL
    const result = await pool.query(
      `SELECT "idEstudio" AS id, "nombreEstudio" AS nombre, "rutaEstudio" AS ruta, "fechaEstudio",
              EXTRACT(EPOCH FROM (NOW() - "fechaEstudio")) / 60 AS "minutosDesde"
       FROM estudios WHERE "IdPaciente" = $1 ORDER BY "fechaEstudio" DESC`,
      [pid]
    );

    // Mapea los resultados, asumiendo que minutosDesde se devuelve correctamente
    const studies = result.rows.map(r => ({
      ...r,
      // PostgreSQL puede devolver minutosDesde como string, convertir a número
      canDelete: (parseFloat(r.minutosDesde) <= 5)
    }));
    res.json(studies);
  } catch (err) {
    console.error('Error fetching studies for patient:', err);
    res.status(500).json({ error: 'DB error retrieving studies' });
  }
});

// Subir estudio
// Asegúrate que el middleware 'upload.single('file')' se ejecute ANTES de tu lógica async
app.post('/api/patients/:id/studies', upload.single('file'), async (req, res) => {
  try {
    const pid = req.params.id; // ID del paciente

    // Verifica si el archivo se subió correctamente por multer
    if (!req.file) {
      console.error('No file received by multer');
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const filename = req.file.filename; // Nombre asignado por multer
    // Crea una ruta relativa estandarizada para guardar en la BD y servir
    // (ej: uploads/patientId/filename.ext)
    // path.relative puede ser complejo en entornos serverless, mejor construirla directamente
    const relativePath = `uploads/${pid}/${filename}`; // Ruta relativa estándar

    console.log(`File uploaded: ${filename}, Path for DB: ${relativePath}, Patient ID: ${pid}`);

    // Inserta en la BD usando marcadores $n y RETURNING para obtener el ID
    const result = await pool.query(
      `INSERT INTO estudios ("rutaEstudio", "nombreEstudio", "IdPaciente", "fechaEstudio")
       VALUES ($1, $2, $3, NOW()) RETURNING "idEstudio"`, // Usa RETURNING y comillas si es necesario
      [relativePath, filename, pid]
    );

    // Verifica si la inserción devolvió el ID
    if (!result.rows || result.rows.length === 0) {
        throw new Error("No se pudo obtener el ID del estudio insertado.");
    }
    const insertedId = result.rows[0].idEstudio; // Accede al ID devuelto (asegúrate que el nombre de columna sea correcto)

    console.log(`Study inserted with ID: ${insertedId}`);

    // Devuelve la información del archivo subido
    res.status(201).json({ // Usa 201 Created para éxito en POST
        id: insertedId,
        nombre: filename,
        ruta: relativePath, // Devuelve la ruta relativa consistente
        canDelete: true // Asume que se puede borrar recién subido
    });

  } catch (err) {
    console.error('Error uploading study:', err);
    // Si hay error, intenta eliminar el archivo físico si se llegó a guardar
    if (req.file && req.file.path) {
        fs.unlink(req.file.path, (unlinkErr) => {
            if (unlinkErr) console.error("Error deleting uploaded file after DB error:", unlinkErr);
        });
    }
    res.status(500).json({ error: 'Upload error', details: err.message });
  }
});


// Eliminar estudio (sólo si <= 5 min)
app.delete('/api/studies/:id', async (req, res) => {
  try {
    const sid = req.params.id;
    // Usa $1 y EXTRACT
    const result = await pool.query(
      `SELECT "idEstudio", "rutaEstudio", "fechaEstudio",
              EXTRACT(EPOCH FROM (NOW() - "fechaEstudio")) / 60 AS "minutosDesde"
       FROM estudios WHERE "idEstudio" = $1`,
      [sid]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Estudio no encontrado' });
    }

    const study = result.rows[0];
    const minutesSince = parseFloat(study.minutosDesde); // Convertir a número

    if (isNaN(minutesSince) || minutesSince > 5) { // Verifica si es NaN también
      return res.status(403).json({ error: 'Tiempo para eliminar expiró o es inválido' });
    }

    // Construye la ruta absoluta basada en UPLOAD_DIR
    // OJO: La ruta guardada es relativa ('uploads/pid/filename'), necesitamos la base
    const filePath = path.join(UPLOAD_DIR, study.rutaEstudio.substring('uploads/'.length)); // Quita 'uploads/' si está al inicio de rutaEstudio

    console.log(`Attempting to delete file: ${filePath}`);

    // Elimina el archivo físico (maneja error si no existe)
    try {
        if (fs.existsSync(filePath)) { // Verifica si existe antes de intentar borrar
             fs.unlinkSync(filePath);
             console.log(`File deleted successfully: ${filePath}`);
        } else {
             console.warn(`File not found for deletion, proceeding with DB delete: ${filePath}`);
        }
    } catch (e) {
      // Loguea el error pero continúa para borrar de la BD
      console.error(`Error deleting file ${filePath}:`, e);
    }

    // Elimina el registro de la base de datos
    await pool.query('DELETE FROM estudios WHERE "idEstudio" = $1', [sid]);
    console.log(`Study record deleted from DB: ${sid}`);

    res.json({ success: true });

  } catch (err) {
    console.error('Error deleting study:', err);
    res.status(500).json({ error: 'Delete error', details: err.message });
  }
});


// --- Endpoint para Chatbot ---
app.post('/api/chatbot', async (req, res) => {
    const userMessage = req.body.message;
    const OPENAI_API_KEY = process.env.OPENAI_API_KEY; // Lee desde variables de entorno

    if (!userMessage || !req.body) {
        return res.status(400).json({ reply: 'Falta el mensaje en la solicitud.' });
    }
    if (!OPENAI_API_KEY) {
        console.error('Error: La variable de entorno OPENAI_API_KEY no está configurada.');
        return res.status(500).json({ reply: 'Error de configuración del servidor del chatbot.' });
    }

    let contextData = ""; // Para guardar datos de la BD

    try {
        // --- Lógica MUY BÁSICA para detectar intención y consultar BD ---
        const lowerMessage = userMessage.toLowerCase();

        if (lowerMessage.includes('quiénes son los pacientes') || lowerMessage.includes('lista de pacientes')) {
            const patientsResult = await pool.query('SELECT nombre FROM pacientes ORDER BY nombre LIMIT 5');
            const patients = patientsResult.rows;
            if (patients.length > 0) {
                contextData = "Pacientes registrados recientemente: " + patients.map(p => p.nombre).join(', ') + ".";
            } else {
                contextData = "No hay pacientes registrados.";
            }
        } else if (lowerMessage.includes('estudios de')) {
            const potentialName = userMessage.substring(userMessage.toLowerCase().indexOf('estudios de') + 12).trim();
            if (potentialName) {
                 const patientResult = await pool.query('SELECT "idPaciente", nombre FROM pacientes WHERE nombre ILIKE $1 LIMIT 1', [`%${potentialName}%`]); // Usa ILIKE para case-insensitive
                 if (patientResult.rows.length > 0) {
                     const patient = patientResult.rows[0];
                     const studiesResult = await pool.query(
                         'SELECT "nombreEstudio" FROM estudios WHERE "IdPaciente" = $1 ORDER BY "fechaEstudio" DESC LIMIT 3',
                         [patient.idPaciente]
                     );
                     const studies = studiesResult.rows;
                     if (studies.length > 0) {
                          contextData = `Estudios recientes para ${patient.nombre}: ${studies.map(s => s.nombreEstudio).join(', ')}.`; // Asegúrate que nombreEstudio sea correcto
                     } else {
                          contextData = `No se encontraron estudios recientes para ${patient.nombre}.`;
                     }
                 } else {
                     contextData = `No se encontró un paciente llamado '${potentialName}'.`;
                 }
            }
        } else if (lowerMessage.includes('doctores') || lowerMessage.includes('usuarios')) {
             const doctorsResult = await pool.query(
                `SELECT u.name FROM users u JOIN roles r ON u."id_Rol" = r."idRol" WHERE r."nombreRol" ILIKE $1 LIMIT 5`, // Usa ILIKE
                ['%Doctor%'] // Busca roles que contengan "Doctor" (case-insensitive)
             );
             const doctors = doctorsResult.rows;
             if (doctors.length > 0) {
                contextData = "Algunos doctores registrados: " + doctors.map(d => d.name).join(', ') + ".";
             } else {
                 contextData = "No se encontraron doctores registrados.";
             }
        }
        // --- Fin Lógica de BD ---

        // --- Llamada a OpenAI ---
        const systemPrompt = "Eres un asistente médico virtual útil para el sistema DICOM System. Responde preguntas sobre pacientes, doctores y estudios médicos de forma concisa. Utiliza la siguiente información de la base de datos SOLO SI es relevante para la pregunta del usuario:";
        const promptMessages = [
            { role: "system", content: systemPrompt + (contextData ? `\n\nContexto de la Base de Datos:\n${contextData}` : "\n(No se recuperó contexto adicional de la base de datos para esta pregunta)") },
            { role: "user", content: userMessage }
        ];

        const openAIResponse = await fetch("https://api.openai.com/v1/chat/completions", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            body: JSON.stringify({
                model: "gpt-3.5-turbo",
                messages: promptMessages,
                max_tokens: 200
            })
        });

        const data = await openAIResponse.json();

        if (!openAIResponse.ok) {
            const errorMessage = data.error?.message || `Error ${openAIResponse.status}`;
            console.error("Error de OpenAI:", data); // Loguea el error completo de OpenAI
            throw new Error(`Error de la API de OpenAI: ${errorMessage}`);
        }

        const botReply = data.choices[0]?.message?.content?.trim() || 'No pude obtener una respuesta del asistente.';

        res.json({ reply: botReply });

    } catch (error) {
        console.error('Error en el endpoint /api/chatbot:', error);
        res.status(500).json({ reply: `Error interno al procesar tu solicitud. Detalles: ${error.message}` });
    }
});


// --- Iniciar Servidor ---
const PORT = process.env.PORT || 3000; // Render asignará el puerto via env var
app.listen(PORT, '0.0.0.0', () => { // Escucha en 0.0.0.0 para ser accesible externamente
    console.log(`API corriendo en puerto ${PORT}`);
});