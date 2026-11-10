/* =====================================================================
   YourShop · Laboratorio de Seguridad Web
   db.js  —  Crea una base de datos SQLite REAL dentro del navegador.
   ---------------------------------------------------------------------
   Usamos sql.js: SQLite compilado a WebAssembly. Las consultas que se
   ejecutan aquí son SQL de verdad, no una simulación. Por eso los
   ataques funcionan de verdad en la versión insegura y fallan de verdad
   en la segura: la diferencia está en el código, no en un "if" que
   detecta el ataque.

   Todo corre en el navegador, con datos inventados. En una aplicación
   real esta base de datos viviría en un SERVIDOR, nunca en el cliente.
   ===================================================================== */

// Catálogo base de YourShop (6 productos reales del proyecto original).
const PRODUCTOS_SEED = [
  { nombre: "Camiseta Oversize Beisbolera 23", categoria: "hombres", precio: 1140,
    img: "assets/CamisaBeisboleraBlanca.jpg", tallas: "S, M, L, XL",
    descripcion: "Camiseta de corte holgado estilo béisbol urbano con cuello en V y detalles en contraste." },
  { nombre: "Conjunto Sporty Sudadera y Pants", categoria: "hombres", precio: 1920,
    img: "assets/ConjuntoDeSudadera.jpg", tallas: "S, M, L",
    descripcion: "Set de dos piezas: sudadera de cuello redondo y pantalón holgado de tiro alto." },
  { nombre: "Pantalon Jogger Wide Leg Dreams", categoria: "hombres", precio: 1350,
    img: "assets/PantalonesDeportivos.jpg", tallas: "S, M, L, XL",
    descripcion: "Pantalón deportivo de corte ancho con cinta ajustable y estampado tipográfico." },
  { nombre: "Top Asimetrico Malla Bordada", categoria: "mujeres", precio: 870,
    img: "assets/CasualTop.jpg", tallas: "XS, S, M, L",
    descripcion: "Top en tejido calado blanco con escote asimétrico de un solo hombro y aro dorado." },
  { nombre: "Vestido Corto Vintage Cerezas", categoria: "mujeres", precio: 1200,
    img: "assets/VestidoBlancoElegante.jpg", tallas: "XS, S, M, L",
    descripcion: "Vestido de tirantes finos con estampado de cerezas y falda acampanada estilo retro." },
  { nombre: "Vestido Romantico Floral", categoria: "mujeres", precio: 1500,
    img: "assets/VestidoEleganteRojo.jpg", tallas: "XS, S, M, L",
    descripcion: "Vestido corto con escote corazón, mangas abullonadas y estampado de microflores." },
];

// Usuarios de prueba. La clave en texto plano es inventada y solo sirve
// para la demostración.
const USUARIOS_SEED = [
  { usuario: "admin", clave: "Admin2026!", rol: "administrador" },
  { usuario: "maria", clave: "maria123",   rol: "cliente" },
];

// Reseñas normales de ejemplo (producto_id arranca en 1).
const RESENAS_SEED = [
  { producto_id: 1, autor: "Carlos",  comentario: "Buena tela, quedó tal como en la foto." },
  { producto_id: 1, autor: "Yarelis", comentario: "Me encantó el corte, pedí la M." },
  { producto_id: 4, autor: "Dayana",  comentario: "El detalle dorado es precioso." },
];

/**
 * Crea y devuelve la base de datos ya sembrada.
 * @param {boolean} seguro  Si es true, las contraseñas se guardan
 *   hasheadas con bcrypt (columna clave_hash). Si es false, se guardan
 *   en texto plano (columna clave), como hacen los sistemas mal hechos.
 */
async function crearBaseDeDatos(seguro) {
  const bcrypt = window.dcodeIO.bcrypt;

  // 1. Arrancar sql.js usando el WebAssembly embebido (sin internet).
  const binario = Uint8Array.from(atob(window.__SQL_WASM_B64__), (c) => c.charCodeAt(0));
  const SQL = await initSqlJs({ wasmBinary: binario });
  const db = new SQL.Database();

  // 2. Esquema.
  db.run(`
    CREATE TABLE usuarios (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario    TEXT NOT NULL,
      clave      TEXT,          -- texto plano: solo la versión insegura
      clave_hash TEXT,          -- hash bcrypt: solo la versión segura
      rol        TEXT NOT NULL DEFAULT 'cliente'
    );
    CREATE TABLE productos (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre      TEXT NOT NULL,
      categoria   TEXT NOT NULL,
      precio      INTEGER NOT NULL,
      img         TEXT,
      tallas      TEXT,
      descripcion TEXT
    );
    CREATE TABLE resenas (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      producto_id INTEGER NOT NULL,
      autor       TEXT NOT NULL,
      comentario  TEXT NOT NULL
    );
  `);

  // 3. Sembrar usuarios (distinto según el modo).
  const insUser = db.prepare(
    "INSERT INTO usuarios (usuario, clave, clave_hash, rol) VALUES (?, ?, ?, ?)"
  );
  for (const u of USUARIOS_SEED) {
    if (seguro) {
      const hash = bcrypt.hashSync(u.clave, 10); // hash único (con salt)
      insUser.run([u.usuario, null, hash, u.rol]);
    } else {
      insUser.run([u.usuario, u.clave, null, u.rol]);
    }
  }
  insUser.free();

  // 4. Sembrar productos.
  const insProd = db.prepare(
    "INSERT INTO productos (nombre, categoria, precio, img, tallas, descripcion) VALUES (?, ?, ?, ?, ?, ?)"
  );
  for (const p of PRODUCTOS_SEED) {
    insProd.run([p.nombre, p.categoria, p.precio, p.img, p.tallas, p.descripcion]);
  }
  insProd.free();

  // 5. Sembrar reseñas.
  const insRes = db.prepare(
    "INSERT INTO resenas (producto_id, autor, comentario) VALUES (?, ?, ?)"
  );
  for (const r of RESENAS_SEED) {
    insRes.run([r.producto_id, r.autor, r.comentario]);
  }
  insRes.free();

  return db;
}

/**
 * Ejecuta una consulta y devuelve { columnas, filas } de forma uniforme,
 * sin importar qué columnas regrese (clave cuando hay un UNION SELECT).
 * Acepta parámetros opcionales para las consultas preparadas.
 */
function ejecutar(db, sql, params) {
  const stmt = db.prepare(sql);
  if (params && params.length) stmt.bind(params);
  const filas = [];
  let columnas = [];
  while (stmt.step()) {
    if (!columnas.length) columnas = stmt.getColumnNames();
    filas.push(stmt.get());
  }
  // Si no hubo filas igual queremos los nombres de columna cuando existan.
  if (!columnas.length) {
    try { columnas = stmt.getColumnNames(); } catch (e) { columnas = []; }
  }
  stmt.free();
  return { columnas, filas };
}

window.crearBaseDeDatos = crearBaseDeDatos;
window.ejecutarSQL = ejecutar;
