/* =====================================================================
   YourShop · Laboratorio de Seguridad Web
   servidor-inseguro.js  —  El "backend" SIN medidas de seguridad.
   ---------------------------------------------------------------------
   Este archivo hace el papel del servidor. En una app real correría en
   Node.js o PHP, separado del navegador. Aquí está escrito a propósito
   CON los errores más comunes, para poder atacarlo en vivo.

   Compáralo línea por línea con servidor-seguro.js: hacen lo mismo,
   pero este concatena la entrada del usuario dentro del SQL.
   ===================================================================== */
(function () {
  let db = null;

  const Servidor = {
    SEGURO: false,

    conectar(base) { db = base; this.__db = base; },

    // ---- LOGIN -------------------------------------------------------
    // ✗ PELIGRO: pega el usuario y la clave directo en la consulta.
    //   Con la clave  ' OR '1'='1  la condición se vuelve siempre verdadera.
    login(usuario, clave) {
      const sql =
        "SELECT * FROM usuarios WHERE usuario='" + usuario + "' AND clave='" + clave + "'";
      let r;
      try {
        r = window.ejecutarSQL(db, sql);
      } catch (e) {
        return { sql, columnas: [], filas: [], sesion: null, error: e.message };
      }
      const fila = r.filas[0];
      const sesion = fila
        ? { usuario: fila[r.columnas.indexOf("usuario")], rol: fila[r.columnas.indexOf("rol")] }
        : null;
      return { sql, columnas: r.columnas, filas: r.filas, sesion };
    },

    // ---- BUSCADOR ----------------------------------------------------
    // ✗ PELIGRO: pega el término en el SQL. Un  ' UNION SELECT ...  deja
    //   que el atacante lea OTRAS tablas (como usuarios) desde el buscador.
    buscar(q) {
      const sql =
        "SELECT nombre, precio FROM productos WHERE nombre LIKE '%" + q + "%'";
      try {
        const r = window.ejecutarSQL(db, sql);
        return { sql, columnas: r.columnas, filas: r.filas, error: null };
      } catch (e) {
        // ✗ Además expone el error crudo del motor: otra pista para el atacante.
        return { sql, columnas: [], filas: [], error: e.message };
      }
    },

    // ---- RESEÑAS -----------------------------------------------------
    listarResenas(productoId) {
      const r = window.ejecutarSQL(
        db, "SELECT autor, comentario FROM resenas WHERE producto_id = " + productoId
      );
      return r.filas.map((f) => ({ autor: f[0], comentario: f[1] }));
    },

    publicarResena(productoId, autor, comentario) {
      // El guardado va parametrizado (el XSS no vive aquí, vive al PINTAR).
      const stmt = db.prepare(
        "INSERT INTO resenas (producto_id, autor, comentario) VALUES (?, ?, ?)"
      );
      stmt.run([productoId, autor || "Anónimo", comentario]);
      stmt.free();
    },

    // ✗ PELIGRO: mete el comentario del usuario con innerHTML.
    //   Si el comentario trae una etiqueta <img onerror=...>, se EJECUTA.
    pintarComentario(elemento, texto) {
      elemento.innerHTML += texto;
    },

    // ---- REGISTRO ----------------------------------------------------
    // ✗ PELIGRO: guarda la contraseña tal cual, en texto plano.
    registrar(usuario, clave) {
      const stmt = db.prepare(
        "INSERT INTO usuarios (usuario, clave, rol) VALUES (?, ?, 'cliente')"
      );
      stmt.run([usuario, clave]);
      stmt.free();
      return { sql: "INSERT INTO usuarios (usuario, clave, rol) VALUES (?, ?, 'cliente')  -- clave en TEXTO PLANO", ok: true };
    },

    // ---- ESPIAR LA BASE DE DATOS (para la demo) ----------------------
    verUsuarios() {
      return window.ejecutarSQL(db, "SELECT id, usuario, clave, clave_hash, rol FROM usuarios");
    },
  };

  window.Servidor = Servidor;
})();
