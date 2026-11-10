# YourShop · Laboratorio de Seguridad Web — Cómo usarlo

**Tecnología de Internet II · ISW-312 · UCE** · Práctica en pareja

Dos versiones de la misma tienda, YourShop. La **insegura** y la **segura**.
La idea es abrir las dos y hacerles los mismos ataques, una al lado de la otra.

---

## 1. Cómo abrirlo (no hay que instalar NADA)

1. Descomprime la carpeta `YourShop-Seguridad`.
2. Entra en la carpeta y haz **doble clic en `inseguro.html`**. Se abre en tu navegador.
3. Abre también `seguro.html` (doble clic) en **otra pestaña**.
4. Ponlas lado a lado (en Chrome: arrastra una pestaña fuera para tener dos ventanas).

> Todo corre dentro del navegador con una base de datos SQLite real (sql.js) y datos
> inventados. **No se conecta a internet ni a ningún servidor.** La primera vez tarda
> uno o dos segundos en arrancar la base de datos ("Iniciando la base de datos…").

**Importante:** la versión insegura es una página realmente vulnerable.
**Nunca la suban a Netlify, GitHub Pages ni a ningún hosting.** Solo se usa en local.

Si una página se "ensucia" después de un ataque (por ejemplo tras el XSS), basta con
**recargarla (F5)**: la base de datos se reinicia desde cero cada vez que se carga.

---

## 2. Los 4 ataques (chuleta rápida)

En ambas páginas hay botones que rellenan el ataque por ti, para no equivocarte en vivo.

| # | Dónde | Qué escribir | Insegura | Segura |
|---|-------|--------------|----------|--------|
| 1 | **Mi cuenta** (login) | Usuario `admin`, contraseña `' OR '1'='1` | Entra como admin sin la clave | "Usuario o contraseña incorrectos" |
| 2 | **Catálogo** (buscar) | `' UNION SELECT usuario, clave FROM usuarios -- ` | Muestra los usuarios y sus claves | Sin resultados |
| 3 | **Reseñas** | `<img src=x onerror="document.getElementById('zona-xss').textContent='⚠ XSS EJECUTADO'">` | Ejecuta el código | Lo muestra como texto |
| 4 | **Crear cuenta** → "Espiar la base de datos" | Registra `pedro` / `pedro999` | La clave se ve tal cual | Se ve el hash `$2a$10$...` |

En cada acción, el **panel oscuro** muestra la consulta SQL que de verdad se ejecutó,
y el **semáforo** (rojo/verde) resume qué pasó.

---

## 3. Qué cambia en el código (para explicarlo)

Todo está en la carpeta `js/`. Las dos versiones comparten `app.js` (la pantalla)
y se diferencian solo en el "servidor":

- `servidor-inseguro.js` → el backend **con los errores**.
- `servidor-seguro.js` → el **mismo** backend, blindado.

| Defensa (clase 05) | Insegura | Segura |
|--------------------|----------|--------|
| Inyección SQL | `"... WHERE usuario='" + usuario + "'"` (pegado) | `"... WHERE usuario = ?"` + parámetro |
| Contraseñas | se guarda `clave` en texto plano | `bcrypt.hashSync(clave, 10)` |
| XSS | `elemento.innerHTML += texto` | `elemento.textContent = texto` |
| Cabeceras | ninguna | CSP (normalmente va como cabecera HTTP con `helmet`) |
| Validación | ninguna | límites de longitud en el servidor |

Abran los dos archivos lado a lado: las partes marcadas con `✗ PELIGRO` y `✓ SEGURO`
señalan exactamente las líneas que cambian.

---

## 4. Contenido de la carpeta

```
YourShop-Seguridad/
├── inseguro.html          ← ábrelo (versión vulnerable, banner rojo)
├── seguro.html            ← ábrelo (versión blindada, banner verde)
├── css/estilos.css
├── js/
│   ├── app.js                 → la pantalla (igual para las dos)
│   ├── db.js                  → crea la base de datos SQLite y la siembra
│   ├── servidor-inseguro.js   → backend vulnerable
│   ├── servidor-seguro.js     → backend seguro
│   └── lib/                    → sql.js (SQLite) y bcrypt, ya incluidos
├── assets/                → las fotos de los productos
└── docs/
    ├── COMO-USARLO.md         → este archivo
    └── GUION-EXPOSICION.md    → el guion para exponer en clase
```
