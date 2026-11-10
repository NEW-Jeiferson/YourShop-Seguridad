/* =====================================================================
   YourShop · Laboratorio de Seguridad Web
   app.js  —  La interfaz (el "cliente"). Es IGUAL para las dos versiones.
   ---------------------------------------------------------------------
   Este archivo no sabe si está hablando con el servidor inseguro o con
   el seguro: solo llama a  Servidor.login(), Servidor.buscar(), etc.
   Esa es justo la idea de la clase 01: el cliente pide, el servidor
   responde. Lo que cambia entre las dos páginas es QUÉ servidor
   responde — no esta pantalla.
   ===================================================================== */
"use strict";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

let Servidor;

document.addEventListener("DOMContentLoaded", async () => {
  Servidor = window.Servidor;

  // Marca visual de la versión.
  document.body.classList.add(Servidor.SEGURO ? "modo-seguro" : "modo-inseguro");

  // Mostrar "cargando" mientras arranca SQLite.
  const estadoCarga = $("#estado-carga");
  try {
    const db = await window.crearBaseDeDatos(Servidor.SEGURO);
    Servidor.conectar(db);
    estadoCarga.remove();
  } catch (e) {
    estadoCarga.textContent = "Error al iniciar la base de datos: " + e.message;
    return;
  }

  renderCatalogo();
  poblarSelectProductos();
  renderResenas(1);
  conectarEventos();
});

/* ---------------------------------------------------------------------
   Helpers de interfaz
   ------------------------------------------------------------------- */
function mostrarConsulta(idPanel, sql) {
  const el = $(idPanel);
  el.hidden = false;
  el.querySelector(".sql").textContent = sql;
}

function setSemaforo(scope, clase, texto) {
  const dot = $(`[data-dot="${scope}"]`);
  const txt = $(`[data-estado="${scope}"]`);
  if (dot) dot.className = "dot " + clase;
  if (txt) txt.textContent = texto;
}

/* ---------------------------------------------------------------------
   1. CATÁLOGO + BUSCADOR  (inyección SQL en la búsqueda)
   ------------------------------------------------------------------- */
function tarjetaProducto(nombre, precioTexto, img, extra) {
  return `
    <article>
      ${img ? `<img src="${esc(img)}" alt="${esc(nombre)}">` : ""}
      <div class="Contenido-Tarjeta">
        <h3 class="Nombre-Producto">${esc(nombre)}</h3>
        <div class="Precio-Producto"><span class="Precio">${esc(precioTexto)}</span></div>
        ${extra || ""}
      </div>
    </article>`;
}

function renderCatalogo() {
  const r = window.ejecutarSQL(dbRef(), "SELECT nombre, precio, img FROM productos");
  const cont = $("#Catalogo");
  cont.innerHTML = r.filas.map((f) =>
    tarjetaProducto(f[0], "DOP " + Number(f[1]).toLocaleString("en-US"), f[2])
  ).join("");
}

// Acceso directo a la base para lecturas de catálogo (lectura normal).
function dbRef() { return Servidor.__db || null; }

function ejecutarBusqueda() {
  const q = $("#input-buscar").value;
  const r = Servidor.buscar(q);
  mostrarConsulta("#panel-buscar", r.sql);

  const cont = $("#Catalogo");
  const idxPrecio = r.columnas.indexOf("precio");

  // Detección REAL de fuga: si el "precio" no es numérico, la fila vino
  // de otra tabla (un UNION SELECT metió texto donde debía ir un número).
  const fuga = r.filas.some((f) => {
    const p = f[idxPrecio];
    return p !== null && p !== undefined && isNaN(Number(p));
  });

  const esIntento = /('|union|--|;|=)/i.test(q);

  if (r.error) {
    cont.innerHTML = `<p class="aviso-error">⚠ El servidor expuso un error de SQL:
      <code>${esc(r.error)}</code><br>Eso ya le dice al atacante que el sitio es vulnerable.</p>`;
    setSemaforo("buscar", "rojo", "Error SQL expuesto");
  } else if (fuga) {
    cont.innerHTML = `
      <p class="aviso-error">⚠ El buscador devolvió datos de OTRA tabla. Esto son credenciales reales, no productos:</p>
      <table class="tabla-fuga"><thead><tr><th>nombre</th><th>precio</th></tr></thead><tbody>
      ${r.filas.map((f) => `<tr><td>${esc(f[0])}</td><td>${esc(f[idxPrecio])}</td></tr>`).join("")}
      </tbody></table>`;
    setSemaforo("buscar", "rojo", "Fuga de datos");
  } else {
    cont.innerHTML = r.filas.length
      ? r.filas.map((f) => tarjetaProducto(f[0], "DOP " + Number(f[idxPrecio]).toLocaleString("en-US"), null)).join("")
      : `<p class="aviso-vacio">Sin resultados para “${esc(q)}”.</p>`;
    if (esIntento && Servidor.SEGURO) setSemaforo("buscar", "verde", "Intento bloqueado");
    else if (esIntento) setSemaforo("buscar", "neutro", "Sin fuga esta vez");
    else setSemaforo("buscar", "neutro", r.filas.length + " resultado(s)");
  }
}

function limpiarBusqueda() {
  $("#input-buscar").value = "";
  $("#panel-buscar").hidden = true;
  setSemaforo("buscar", "neutro", "En espera");
  renderCatalogo();
}

/* ---------------------------------------------------------------------
   2. LOGIN  (inyección SQL en el inicio de sesión)
   ------------------------------------------------------------------- */
function ejecutarLogin(e) {
  if (e) e.preventDefault();
  const usuario = $("#login-usuario").value;
  const clave = $("#login-clave").value;
  const r = Servidor.login(usuario, clave);
  mostrarConsulta("#panel-login", r.sql);

  const esIntento = /('|--|\bor\b|=)/i.test(usuario) || /('|--|\bor\b|=)/i.test(clave);
  const salida = $("#login-resultado");

  if (r.sesion) {
    salida.className = "resultado " + (esIntento ? "malo" : "ok");
    salida.innerHTML = esIntento
      ? `⚠ Acceso concedido como <b>${esc(r.sesion.usuario)}</b> (rol: ${esc(r.sesion.rol)}) <b>sin la contraseña correcta</b>.`
      : `✓ Bienvenido, <b>${esc(r.sesion.usuario)}</b> (rol: ${esc(r.sesion.rol)}).`;
    setSemaforo("login", esIntento ? "rojo" : "neutro", esIntento ? "Bypass de login" : "Login normal");
  } else {
    salida.className = "resultado neutro";
    salida.textContent = "Usuario o contraseña incorrectos.";
    setSemaforo("login", esIntento && Servidor.SEGURO ? "verde" : "neutro",
      esIntento && Servidor.SEGURO ? "Intento bloqueado" : "Credenciales incorrectas");
  }
}

/* ---------------------------------------------------------------------
   3. RESEÑAS  (XSS: código del usuario que se ejecuta)
   ------------------------------------------------------------------- */
function poblarSelectProductos() {
  const r = window.ejecutarSQL(dbRef(), "SELECT id, nombre FROM productos");
  $("#resena-producto").innerHTML = r.filas
    .map((f) => `<option value="${f[0]}">${esc(f[1])}</option>`).join("");
}

function renderResenas(productoId) {
  const lista = $("#lista-resenas");
  lista.innerHTML = "";
  const resenas = Servidor.listarResenas(productoId);
  if (!resenas.length) { lista.innerHTML = `<p class="aviso-vacio">Aún no hay reseñas.</p>`; return; }
  resenas.forEach((rv) => {
    const item = document.createElement("div");
    item.className = "resena";
    const autor = document.createElement("strong");
    autor.textContent = rv.autor + ": ";
    const cuerpo = document.createElement("span");
    // Aquí está la diferencia: el servidor decide CÓMO se pinta el texto.
    Servidor.pintarComentario(cuerpo, rv.comentario);
    item.appendChild(autor);
    item.appendChild(cuerpo);
    lista.appendChild(item);
  });
}

function publicarResena(e) {
  if (e) e.preventDefault();
  const productoId = Number($("#resena-producto").value);
  const autor = $("#resena-autor").value;
  const comentario = $("#resena-texto").value;
  if (!comentario.trim()) return;
  Servidor.publicarResena(productoId, autor, comentario);
  $("#resena-texto").value = "";
  renderResenas(productoId);
  setSemaforo("xss", Servidor.SEGURO ? "verde" : "neutro",
    Servidor.SEGURO ? "Se muestra como texto" : "Publicada");
}

/* ---------------------------------------------------------------------
   4. REGISTRO + ESPIAR LA BASE DE DATOS  (contraseñas: texto plano vs hash)
   ------------------------------------------------------------------- */
function registrarUsuario(e) {
  if (e) e.preventDefault();
  const usuario = $("#reg-usuario").value.trim();
  const clave = $("#reg-clave").value;
  if (!usuario || !clave) return;
  const r = Servidor.registrar(usuario, clave);
  mostrarConsulta("#panel-registro", r.sql);
  $("#reg-usuario").value = "";
  $("#reg-clave").value = "";
  $("#reg-resultado").textContent = `Usuario “${usuario}” registrado. Pulsa “Espiar la base de datos” para ver cómo quedó guardada su contraseña.`;
}

function espiarBaseDeDatos() {
  const r = Servidor.verUsuarios();
  const cont = $("#tabla-usuarios");
  const encabezados = r.columnas.map((c) => `<th>${esc(c)}</th>`).join("");
  const filas = r.filas.map((f) => "<tr>" + f.map((v, i) => {
    const col = r.columnas[i];
    let celda = v === null || v === undefined ? "—" : String(v);
    let clase = "";
    if (col === "clave" && v) clase = "celda-peligro";       // texto plano = malo
    if (col === "clave_hash" && v) clase = "celda-ok";        // hash = bien
    return `<td class="${clase}">${esc(celda)}</td>`;
  }).join("") + "</tr>").join("");
  cont.innerHTML = `<table class="tabla-db"><thead><tr>${encabezados}</tr></thead><tbody>${filas}</tbody></table>`;
  cont.hidden = false;
}

/* ---------------------------------------------------------------------
   Conexión de eventos + modo oscuro
   ------------------------------------------------------------------- */
function conectarEventos() {
  $("#form-buscar").addEventListener("submit", (e) => { e.preventDefault(); ejecutarBusqueda(); });
  $("#btn-limpiar").addEventListener("click", limpiarBusqueda);
  $("#form-login").addEventListener("submit", ejecutarLogin);
  $("#resena-producto").addEventListener("change", (e) => renderResenas(Number(e.target.value)));
  $("#form-resena").addEventListener("submit", publicarResena);
  $("#form-registro").addEventListener("submit", registrarUsuario);
  $("#btn-espiar").addEventListener("click", espiarBaseDeDatos);
  $("#btn-modo").addEventListener("click", () => document.body.classList.toggle("modo-oscuro"));

  // Botones que rellenan los ataques de ejemplo (para la demo en vivo).
  document.querySelectorAll("[data-fill]").forEach((b) =>
    b.addEventListener("click", () => {
      const destino = $(b.dataset.fill);
      destino.value = b.dataset.valor;
      destino.focus();
    }));
}
