const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const catalog = require('./catalog.json');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : undefined,
  max: 10,
  connectionTimeoutMillis: 10000
});
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'https://images.unsplash.com'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: '100kb' }));
app.use(session({
  store: new PgSession({ pool, tableName: 'web_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'local-only-change-before-deploy',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProduction, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 14 }
}));

const schema = `
CREATE TABLE IF NOT EXISTS customers (
  customer_id BIGSERIAL PRIMARY KEY,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS store_products (
  product_id INTEGER PRIMARY KEY,
  product_name VARCHAR(120) NOT NULL,
  price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
  stock_quantity INTEGER NOT NULL CHECK (stock_quantity >= 0)
);
CREATE TABLE IF NOT EXISTS customer_carts (
  customer_id BIGINT PRIMARY KEY REFERENCES customers(customer_id) ON DELETE CASCADE,
  items JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS customer_favorites (
  customer_id BIGINT PRIMARY KEY REFERENCES customers(customer_id) ON DELETE CASCADE,
  product_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS store_orders (
  order_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_number VARCHAR(20) NOT NULL UNIQUE,
  customer_id BIGINT NOT NULL REFERENCES customers(customer_id),
  order_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  total_cents INTEGER NOT NULL CHECK (total_cents >= 0),
  order_status VARCHAR(20) NOT NULL DEFAULT 'Placed',
  payment_method VARCHAR(40) NOT NULL,
  payment_status VARCHAR(40) NOT NULL,
  shipping_address TEXT NOT NULL,
  phone_number VARCHAR(30) NOT NULL
);
CREATE TABLE IF NOT EXISTS store_order_items (
  order_item_id BIGSERIAL PRIMARY KEY,
  order_id UUID NOT NULL REFERENCES store_orders(order_id) ON DELETE CASCADE,
  product_id INTEGER NOT NULL REFERENCES store_products(product_id),
  product_name VARCHAR(120) NOT NULL,
  quantity INTEGER NOT NULL CHECK (quantity > 0),
  unit_price_cents INTEGER NOT NULL CHECK (unit_price_cents >= 0)
);
CREATE TABLE IF NOT EXISTS store_payments (
  payment_id BIGSERIAL PRIMARY KEY,
  order_id UUID NOT NULL UNIQUE REFERENCES store_orders(order_id) ON DELETE CASCADE,
  amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
  payment_method VARCHAR(40) NOT NULL,
  payment_status VARCHAR(40) NOT NULL,
  payment_date TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`;

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, saved) {
  const [salt, expectedHex] = saved.split(':');
  const expected = Buffer.from(expectedHex, 'hex');
  const actual = crypto.scryptSync(password, salt, expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
function requireUser(req, res, next) {
  if (!req.session.customerId) return res.status(401).json({ error: 'Please sign in.' });
  next();
}
function originGuard(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== `${req.protocol}://${req.get('host')}`) return res.status(403).json({ error: 'Request origin not allowed.' });
  next();
}
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 15, standardHeaders: 'draft-8', legacyHeaders: false });
function toClientOrder(row, items) {
  return {
    id: row.order_number,
    date: new Date(row.order_date).toISOString(),
    items: items.map(item => ({ id: Number(item.product_id), name: item.product_name, price: Number(item.unit_price_cents) / 100, quantity: Number(item.quantity) })),
    total: Number(row.total_cents) / 100,
    paymentMethod: row.payment_method,
    paymentStatus: row.payment_status,
    status: row.order_status,
    address: row.shipping_address
  };
}
async function loadOrders(customerId) {
  const { rows } = await pool.query('SELECT * FROM store_orders WHERE customer_id=$1 ORDER BY order_date DESC', [customerId]);
  if (!rows.length) return [];
  const ids = rows.map(row => row.order_id);
  const items = await pool.query('SELECT * FROM store_order_items WHERE order_id = ANY($1::uuid[]) ORDER BY order_item_id', [ids]);
  const byOrder = new Map();
  for (const item of items.rows) {
    const key = String(item.order_id);
    if (!byOrder.has(key)) byOrder.set(key, []);
    byOrder.get(key).push(item);
  }
  return rows.map(row => toClientOrder(row, byOrder.get(String(row.order_id)) || []));
}
async function start() {
  await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');
  await pool.query(schema);
  for (const product of catalog) {
    await pool.query(
      `INSERT INTO store_products(product_id,product_name,price_cents,stock_quantity)
       VALUES($1,$2,$3,$4)
       ON CONFLICT(product_id) DO UPDATE SET product_name=EXCLUDED.product_name,price_cents=EXCLUDED.price_cents`,
      [product.id, product.name, Math.round(product.price * 100), product.stock]
    );
  }

  app.get('/api/health', async (_req, res) => {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  });
  app.get('/api/products', async (_req, res) => {
    const { rows } = await pool.query('SELECT product_id,price_cents,stock_quantity FROM store_products');
    res.json(rows.map(p => ({ id: Number(p.product_id), price: Number(p.price_cents) / 100, stock: Number(p.stock_quantity) })));
  });
  app.post('/api/auth/register', authLimit, originGuard, async (req, res) => {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2 || name.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 200) {
      return res.status(400).json({ error: 'Enter a valid name and email, and a password with at least 8 characters.' });
    }
    try {
      const { rows } = await pool.query('INSERT INTO customers(full_name,email,password_hash) VALUES($1,$2,$3) RETURNING customer_id,full_name,email', [name,email,hashPassword(password)]);
      req.session.customerId = rows[0].customer_id;
      res.status(201).json({ user: { id: Number(rows[0].customer_id), name: rows[0].full_name, email: rows[0].email } });
    } catch (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'That email already has an account. Sign in instead.' });
      throw error;
    }
  });
  app.post('/api/auth/login', authLimit, originGuard, async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const { rows } = await pool.query('SELECT customer_id,full_name,email,password_hash FROM customers WHERE email=$1', [email]);
    if (!rows.length || !verifyPassword(password, rows[0].password_hash)) return res.status(401).json({ error: 'Email or password is incorrect.' });
    req.session.customerId = rows[0].customer_id;
    res.json({ user: { id: Number(rows[0].customer_id), name: rows[0].full_name, email: rows[0].email } });
  });
  app.post('/api/auth/logout', originGuard, (req, res) => req.session.destroy(() => {
    res.clearCookie('connect.sid', { httpOnly: true, secure: isProduction, sameSite: 'lax' });
    res.json({ ok: true });
  }));
  app.get('/api/auth/me', requireUser, async (req, res) => {
    const { rows } = await pool.query('SELECT customer_id,full_name,email FROM customers WHERE customer_id=$1', [req.session.customerId]);
    if (!rows.length) return res.status(401).json({ error: 'Please sign in.' });
    res.json({ user: { id: Number(rows[0].customer_id), name: rows[0].full_name, email: rows[0].email } });
  });
  app.get('/api/cart', requireUser, async (req,res) => {
    const { rows } = await pool.query('SELECT items FROM customer_carts WHERE customer_id=$1', [req.session.customerId]);
    res.json(rows[0]?.items || {});
  });
  app.put('/api/cart', requireUser, originGuard, async (req,res) => {
    const input = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
    const cart = {};
    for (const [id,qtyRaw] of Object.entries(input)) {
      const qty = Math.floor(Number(qtyRaw));
      if (!Number.isInteger(Number(id)) || qty < 1 || qty > 999) continue;
      cart[Number(id)] = qty;
    }
    await pool.query('INSERT INTO customer_carts(customer_id,items,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(customer_id) DO UPDATE SET items=EXCLUDED.items,updated_at=NOW()', [req.session.customerId,cart]);
    res.json(cart);
  });
  app.get('/api/favorites', requireUser, async (req,res) => {
    const { rows } = await pool.query('SELECT product_ids FROM customer_favorites WHERE customer_id=$1', [req.session.customerId]);
    res.json(rows[0]?.product_ids || []);
  });
  app.put('/api/favorites', requireUser, originGuard, async (req,res) => {
    const ids = [...new Set((Array.isArray(req.body?.ids) ? req.body.ids : []).map(Number).filter(id=>catalog.some(p=>p.id===id)))];
    await pool.query('INSERT INTO customer_favorites(customer_id,product_ids,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(customer_id) DO UPDATE SET product_ids=EXCLUDED.product_ids,updated_at=NOW()', [req.session.customerId,ids]);
    res.json(ids);
  });
  app.get('/api/orders', requireUser, async (req,res) => res.json(await loadOrders(req.session.customerId)));
  app.post('/api/orders', requireUser, originGuard, async (req,res) => {
    const items = Array.isArray(req.body?.items) ? req.body.items : [];
    const method = String(req.body?.paymentMethod || '');
    const allowedMethods = ['UPI','Credit / Debit Card','Net Banking','Cash on Delivery'];
    const address = String(req.body?.address || '').trim().slice(0,500);
    const phone = String(req.body?.phone || '').trim().slice(0,30);
    if (!items.length || !allowedMethods.includes(method) || address.length < 8 || phone.length < 8) return res.status(400).json({error:'Complete delivery details and choose a payment method.'});
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const prepared=[];
      let total=0;
      for (const item of items) {
        const id=Number(item.id), quantity=Math.floor(Number(item.quantity));
        if (!Number.isInteger(id)||!Number.isInteger(quantity)||quantity<1||quantity>25) throw Object.assign(new Error('Invalid item quantity.'),{status:400});
        const result=await client.query('SELECT product_id,product_name,price_cents,stock_quantity FROM store_products WHERE product_id=$1 FOR UPDATE',[id]);
        if (!result.rows.length||result.rows[0].stock_quantity<quantity) throw Object.assign(new Error('Some products no longer have enough stock.'),{status:409});
        const product=result.rows[0];
        prepared.push({product,quantity});
        total+=Number(product.price_cents)*quantity;
      }
      const paymentStatus=method==='Cash on Delivery'?'Pending':'Demo success';
      const orderNumber='NV'+Date.now().toString().slice(-8);
      const created=await client.query('INSERT INTO store_orders(order_number,customer_id,total_cents,payment_method,payment_status,shipping_address,phone_number) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[orderNumber,req.session.customerId,total,method,paymentStatus,address,phone]);
      for (const line of prepared) {
        await client.query('INSERT INTO store_order_items(order_id,product_id,product_name,quantity,unit_price_cents) VALUES($1,$2,$3,$4,$5)',[created.rows[0].order_id,line.product.product_id,line.product.product_name,line.quantity,line.product.price_cents]);
        await client.query('UPDATE store_products SET stock_quantity=stock_quantity-$1 WHERE product_id=$2',[line.quantity,line.product.product_id]);
      }
      await client.query('INSERT INTO store_payments(order_id,amount_cents,payment_method,payment_status) VALUES($1,$2,$3,$4)',[created.rows[0].order_id,total,method,paymentStatus]);
      await client.query('UPDATE customer_carts SET items=$1,updated_at=NOW() WHERE customer_id=$2',['{}',req.session.customerId]);
      await client.query('COMMIT');
      const orders=await loadOrders(req.session.customerId);
      res.status(201).json({order:orders.find(o=>o.id===orderNumber)});
    } catch(error) {
      await client.query('ROLLBACK');
      res.status(error.status||500).json({error:error.status?error.message:'Could not place the order.'});
    } finally { client.release(); }
  });
  app.post('/api/orders/:orderNumber/actions', requireUser, originGuard, async (req,res) => {
    const action=String(req.body?.action||'');
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const result=await client.query('SELECT * FROM store_orders WHERE order_number=$1 AND customer_id=$2 FOR UPDATE',[req.params.orderNumber,req.session.customerId]);
      if(!result.rows.length){await client.query('ROLLBACK');return res.status(404).json({error:'Order not found.'})}
      const order=result.rows[0];
      if(action==='cancel'){
        if(!['Placed','Processing'].includes(order.order_status)){await client.query('ROLLBACK');return res.status(409).json({error:'This order can no longer be cancelled.'})}
        await client.query("UPDATE store_orders SET order_status='Cancelled',payment_status=$1 WHERE order_id=$2",[order.payment_method==='Cash on Delivery'?'Not charged':'Refund initiated (demo)',order.order_id]);
        await client.query("UPDATE store_payments SET payment_status=$1 WHERE order_id=$2",[order.payment_method==='Cash on Delivery'?'Not charged':'Refund initiated (demo)',order.order_id]);
        await client.query('UPDATE store_products p SET stock_quantity=p.stock_quantity+i.quantity FROM store_order_items i WHERE i.order_id=$1 AND p.product_id=i.product_id',[order.order_id]);
      } else if(action==='advance'){
        const stages=['Placed','Processing','Shipped','Delivered'],index=stages.indexOf(order.order_status);
        if(index<0||index>=stages.length-1){await client.query('ROLLBACK');return res.status(409).json({error:'No further tracking update is available.'})}
        await client.query('UPDATE store_orders SET order_status=$1 WHERE order_id=$2',[stages[index+1],order.order_id]);
      } else {await client.query('ROLLBACK');return res.status(400).json({error:'Unknown action.'})}
      await client.query('COMMIT');
      const orders=await loadOrders(req.session.customerId);
      res.json({order:orders.find(o=>o.id===order.order_number)});
    } catch(error) { await client.query('ROLLBACK');res.status(500).json({error:'Could not update the order.'}) }
    finally {client.release()}
  });
  app.use(express.static(__dirname,{extensions:['html']}));
  app.get('*path',(_req,res)=>res.sendFile(path.join(__dirname,'index.html')));
  app.use((error,_req,res,_next)=>{console.error(error);res.status(500).json({error:'A server error occurred.'})});
  const port=process.env.PORT||10000;
  app.listen(port,'0.0.0.0',()=>console.log(`Nuvora listening on ${port}`));
}
start().catch(error=>{console.error('Startup failed',error);process.exit(1)});
