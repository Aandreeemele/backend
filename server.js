const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');

const app = express();
const port = 3000;


app.use(express.json());
app.use(cors());


const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Diami2025',
    database: 'todo_list',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


async function conectar(consulta_sql) {
    try {
        const conexion = await pool.getConnection();
        console.log("Conexión exitosa a la base de datos.");

        const [rows] = await conexion.execute(consulta_sql);
        conexion.release();

        return rows;
    } catch (error) {
        console.error("Error al conectar a la base de datos:", error);
        return null;
    }
}

app.get('/tareas', async (req, res) => {
    const resultado = await conectar("SELECT * FROM tareas");
    res.json(resultado);
});


app.post('/tareas', async (req, res) => {
    const { descripcion } = req.body;
    const consulta_sql = `INSERT INTO tareas (descripcion) VALUES ('${descripcion}')`;
    const resultado = await conectar(consulta_sql);
    res.json(resultado);
});

app.put('/tareas/:id', async (req, res) => {
    const { id } = req.params;
    const { completada } = req.body;
    const consulta_sql = `UPDATE tareas SET completada = ${completada} WHERE id = ${id}`;
    const resultado = await conectar(consulta_sql);
    res.json(resultado);
});

app.delete('/tareas/:id', async (req, res) => {
    const { id } = req.params;
    const consulta_sql = `DELETE FROM tareas WHERE id = ${id}`;
    const resultado = await conectar(consulta_sql);
    res.json(resultado);
});


app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});

module.exports = app;