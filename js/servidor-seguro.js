/* =====================================================================
   YourShop · Laboratorio de Seguridad Web
   servidor-seguro.js  —  El MISMO backend, pero BLINDADO.
   ---------------------------------------------------------------------
   Hace exactamente lo mismo que servidor-inseguro.js. Cambian pocas
   líneas, y cada cambio sale directo de la clase 05:
     · Consultas preparadas (?)  →  frenan la inyección SQL.
     · bcrypt para las claves    →  nunca se guardan en texto plano.
     · textContent al pintar     →  frena el XSS.
     · validación en el servidor →  límites de longitud.
   La CSP (otra barrera contra XSS) se activa con un <meta> en el HTML.
   ===================================================================== */
(function () {
  let db = null;
  const bcrypt = window.dcodeIO.bcrypt;

  const Servidor = {
    SEGURO: true,

    conectar(base) { db = base; this.__db = base; },

    // ---- LOGIN -------------------------------------------------------
    // ✓ SEGURO: el usuario viaja como PARÁMETRO (?), nunca pegado.
    //   Y la clave se compara con su hash bcrypt, no en texto plano.
    login(usuario, clave) {
      const sql = "SELECT * FROM usuarios WHERE usuario = ?";
      const r = window.ejecutarSQL(db, sql, [usuario]);
      const fila = r.filas[0];
      let sesion = null;
      if (fila) {
        const hash = fila[r.columnas.indexOf("clave_hash")];
        if (hash && bcrypt.compareSync(clave, hash)) {
          sesion = { usuario: fila[r.columnas.indexOf("usuario")], rol: fila[r.columnas.indexOf("rol")] };
        }
      }
      // Lo que se muestra en el panel: la consulta con el dato aparte.
      const sqlMostrado = 'SELECT * FROM usuarios WHERE usuario = ?   -- parámetro: ["' + usuario + '"]';
      return { sql: sqlMostrado, columnas: r.columnas, filas: sesion ? r.filas : [], sesion };
    },

    // ---- BUSCADOR ----------------------------------------------------
    // ✓ SEGURO: el término viaja como parámetro. UNION SELECT se busca
    //   como texto literal entre los nombres: no lee otras tablas.
    buscar(q) {
      q = String(q).slice(0, 60); // validación: límite de longitud
      const sql = "SELECT nombre, precio FROM productos WHERE nombre LIKE ?";
      let r;
      try {
        r = window.ejecutarSQL(db, sql, ["%" + q + "%"]);
      } catch (e) {
        // El error queda en el "servidor", no se le muestra al usuario.
        console.error(e);
        return { sql, columnas: ["nombre", "precio"], filas: [], error: null };
      }
      const sqlMostrado = 'SELECT nombre, precio FROM productos WHERE nombre LIKE ?   -- parámetro: ["%' + q + '%"]';
      return { sql: sqlMostrado, columnas: r.columnas, filas: r.filas, error: null };
    },

    // ---- RESEÑAS -----------------------------------------------------
    listarResenas(productoId) {
      const r = window.ejecutarSQL(
        db, "SELECT autor, comentario FROM resenas WHERE producto_id = ?", [productoId]
      );
      return r.filas.map((f) => ({ autor: f[0], comentario: f[1] }));
    },

    publicarResena(productoId, autor, comentario) {
      autor = String(autor || "Anónimo").slice(0, 40);     // validación
      comentario = String(comentario).slice(0, 280);        // validación
      const stmt = db.prepare(
        "INSERT INTO resenas (producto_id, autor, comentario) VALUES (?, ?, ?)"
      );
      stmt.run([productoId, autor, comentario]);
      stmt.free();
    },

    // ✓ SEGURO: usa textContent. El comentario se muestra como TEXTO,
    //   nunca se interpreta como HTML, así que el <img onerror> no corre.
    pintarComentario(elemento, texto) {
      const linea = document.createElement("span");
      linea.textContent = texto;
      elemento.appendChild(linea);
    },

    // ---- REGISTRO ----------------------------------------------------
    // ✓ SEGURO: guarda el HASH bcrypt, nunca la clave real.
    registrar(usuario, clave) {
      const hash = bcrypt.hashSync(clave, 10);
      const stmt = db.prepare(
        "INSERT INTO usuarios (usuario, clave_hash, rol) VALUES (?, ?, 'cliente')"
      );
      stmt.run([usuario, hash]);
      stmt.free();
      return { sql: "INSERT INTO usuarios (usuario, clave_hash, rol) VALUES (?, ?, 'cliente')  -- bcrypt.hashSync(clave, 10)", ok: true };
    },

    // ---- ESPIAR LA BASE DE DATOS (para la demo) ----------------------
    verUsuarios() {
      return window.ejecutarSQL(db, "SELECT id, usuario, clave, clave_hash, rol FROM usuarios");
    },
  };

  window.Servidor = Servidor;
})();
