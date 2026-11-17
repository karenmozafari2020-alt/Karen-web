import 'dotenv/config';
import express from 'express';
import { createClient } from '@supabase/supabase-js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '200kb' }));

const PORT = process.env.PORT || 3000;
const SITE_URL = (process.env.SITE_URL || '').replace(/\/$/, '');
const PAYMENT_MODE = (process.env.PAYMENT_MODE || 'demo').toLowerCase();
const SANDBOX = (process.env.ZARINPAL_SANDBOX || 'true').toLowerCase() === 'true';
const MERCHANT_ID = process.env.ZARINPAL_MERCHANT_ID || '';
const BUCKET = process.env.SUPABASE_BUCKET || 'template-files';
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'KARENONE').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';

const dbReady = Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);
const db = dbReady ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
}) : null;

const demoProducts = [
  { id:'demo-1', title:'NOVA — قالب گیمینگ', category:'گیمینگ', description:'قالب تیره و مدرن برای کامیونیتی و فروشگاه بازی.', price_rial:12500000, image_url:'', featured:true },
  { id:'demo-2', title:'ÉLITE — قالب شرکتی', category:'شرکتی', description:'طراحی رسمی و مینیمال برای معرفی کسب‌وکار.', price_rial:9800000, image_url:'', featured:true },
  { id:'demo-3', title:'LUMI — قالب فروشگاهی', category:'فروشگاهی', description:'صفحه محصول، دسته‌بندی و تجربه خرید ساده.', price_rial:14900000, image_url:'', featured:false },
  { id:'demo-4', title:'MONO — قالب شخصی', category:'شخصی', description:'نمونه‌کار و رزومه با ظاهر مینیمال.', price_rial:7500000, image_url:'', featured:false }
];

function timingSafeEqualText(a, b) {
  const x = Buffer.from(String(a ?? ''));
  const y = Buffer.from(String(b ?? ''));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function validUsername(username) {
  return typeof username === 'string' && /^[a-zA-Z0-9_]{3,24}$/.test(username);
}
function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token) {
  if (!token || !SESSION_SECRET) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(parts[0]).digest('base64url');
  if (!timingSafeEqualText(parts[1], expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
function setSession(res, user) {
  const token = signToken({ id:user.id, username:user.username, role:user.role, exp:Date.now() + 1000*60*60*24*7 });
  res.cookie('kw_session', token, {
    httpOnly:true, secure:process.env.NODE_ENV === 'production', sameSite:'lax',
    maxAge:7*24*60*60*1000, path:'/'
  });
}
function currentUser(req) {
  const token = req.cookies?.kw_session || '';
  return verifyToken(token);
}
function auth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error:'برای ادامه ابتدا وارد حساب کاربری شوید.' });
  req.user = user; next();
}
function admin(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'admin' || req.user.username !== ADMIN_USERNAME)
      return res.status(403).json({ error:'فقط حساب مالک KAREN WEB به این بخش دسترسی دارد.' });
    next();
  });
}
function requireDb(req, res, next) {
  if (!db) return res.status(503).json({ error:'اتصال Supabase هنوز تنظیم نشده است.' });
  next();
}
function asyncRoute(fn) { return (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next); }

app.use((req,res,next) => {
  const cookies = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > -1) cookies[part.slice(0,i).trim()] = decodeURIComponent(part.slice(i+1).trim());
  }
  req.cookies = cookies; next();
});

async function ensureOwnerAccount() {
  if (!db || !ADMIN_PASSWORD || !SESSION_SECRET) {
    console.warn('Owner account bootstrap skipped: configure Supabase, ADMIN_PASSWORD and SESSION_SECRET.');
    return;
  }
  if (!validUsername(ADMIN_USERNAME)) throw new Error('ADMIN_USERNAME must be 3-24 letters/numbers/underscores.');
  const { data: found, error: findError } = await db.from('users').select('id,role').eq('username', ADMIN_USERNAME).maybeSingle();
  if (findError) throw findError;
  if (!found) {
    const salt = crypto.randomBytes(16).toString('hex');
    const { error } = await db.from('users').insert({
      username: ADMIN_USERNAME, password_salt:salt,
      password_hash:hashPassword(ADMIN_PASSWORD,salt), role:'admin'
    });
    if (error) throw error;
    console.log(`Owner account ${ADMIN_USERNAME} created.`);
  } else if (found.role !== 'admin') {
    const { error } = await db.from('users').update({ role:'admin' }).eq('id', found.id);
    if (error) throw error;
      }
}

app.get('/api/messages',auth,requireDb,asyncRoute(async(req,res)=>{
  let query=db.from('messages')
    .select('id,user_id,sender_role,body,created_at')
    .order('created_at',{ascending:true})
    .limit(150);

  if(req.user.role!=='admin') {
    query=query.eq('user_id',req.user.id);
  }

  const {data:messages,error}=await query;

  if(error) {
    return res.status(500).json({
      error:'دریافت پیام‌ها ناموفق بود.'
    });
  }

  const userIds=[...new Set((messages||[]).map(m=>m.user_id))];
  const usernames=new Map();

  if(userIds.length) {
    const {data:accounts,error:userError}=await db
      .from('users')
      .select('id,username')
      .in('id',userIds);

    if(userError) throw userError;

    for(const account of accounts||[]) {
      usernames.set(account.id,account.username);
    }
  }

  const result=(messages||[]).map(m=>({
    ...m,
    sender_name:m.sender_role==='admin'
      ? 'مدیر'
      : (usernames.get(m.user_id)||'کاربر')
  }));

  res.json(result);
}));





app.post('/api/auth/register', requireDb, asyncRoute(async (req,res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (!validUsername(username)) {
    return res.status(400).json({
      error: 'نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا _ باشد.'
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: 'رمز عبور باید حداقل ۸ کاراکتر باشد.'
    });
  }

  if (username === ADMIN_USERNAME) {
    return res.status(409).json({
      error: 'این نام کاربری مخصوص حساب مالک است.'
    });
  }

  const salt = crypto.randomBytes(16).toString('hex');

  const { data, error } = await db.from('users').insert({
    username,
    password_salt: salt,
    password_hash: hashPassword(password, salt),
    role: 'customer'
  }).select('id,username,role').single();

  if (error) {
    console.error('REGISTER DATABASE ERROR:', {
      code: error.code,
      message: error.message,
      details: error.details,
      hint: error.hint
    });

    if (error.code === '23505') {
      return res.status(409).json({
        error: 'این نام کاربری قبلاً ثبت شده است.'
      });
    }

    return res.status(500).json({
      error: 'ثبت‌نام انجام نشد. کد خطا: ' + (error.code || 'UNKNOWN')
    });
  }

  setSession(res, data);

  return res.json({
    ok: true,
    user: {
      username: data.username,
      role: data.role
    }
  });
}));

app.post('/api/auth/login', requireDb, asyncRoute(async (req,res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const { data:user, error } = await db.from('users').select('id,username,password_hash,password_salt,role').eq('username',username).maybeSingle();
  if (error || !user || !timingSafeEqualText(hashPassword(password,user.password_salt),user.password_hash))
    return res.status(401).json({error:'نام کاربری یا رمز عبور اشتباه است.'});
  setSession(res,user);
  res.json({ok:true,user:{username:user.username,role:user.role}});
}));
app.post('/api/auth/logout', (req,res) => {
  res.clearCookie('kw_session',{path:'/'});
  res.json({ok:true});
});
app.get('/api/auth/me', (req,res) => {
  const u=currentUser(req);
  res.json({user:u?{username:u.username,role:u.role}:null});
});

app.get('/api/products', asyncRoute(async (req,res) => {
  if (!db) return res.json(demoProducts);
  const {data,error}=await db.from('products').select('id,title,category,description,price_rial,image_url,featured')
    .eq('active',true).order('featured',{ascending:false}).order('created_at',{ascending:false});
  if(error) return res.status(500).json({error:'دریافت محصولات انجام نشد.'});
  res.json(data||[]);
}));

app.get('/admin', (req,res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.use(express.static(path.join(__dirname,'public')));

app.post('/api/admin/products', admin, requireDb, asyncRoute(async(req,res)=>{
  const b=req.body||{}, price=Number(b.price_rial);
  if(!String(b.title||'').trim()||!Number.isSafeInteger(price)||price<=0)
    return res.status(400).json({error:'عنوان و قیمت صحیح به ریال لازم است.'});
  const row={title:String(b.title).trim().slice(0,100),category:String(b.category||'عمومی').slice(0,40),
    description:String(b.description||'').slice(0,1000),price_rial:price,image_url:String(b.image_url||'').slice(0,1000),
    storage_path:String(b.storage_path||'').slice(0,500),featured:Boolean(b.featured),active:true};
  const {data,error}=await db.from('products').insert(row).select().single();
  if(error) return res.status(500).json({error:'ذخیره محصول ناموفق بود.'});
  res.json({ok:true,product:data});
}));
app.patch('/api/admin/products/:id', admin, requireDb, asyncRoute(async(req,res)=>{
  const keys=['title','category','description','price_rial','image_url','storage_path','featured','active'], patch={};
  for(const k of keys) if(k in (req.body||{})) patch[k]=req.body[k];
  if('price_rial' in patch){patch.price_rial=Number(patch.price_rial);if(!Number.isSafeInteger(patch.price_rial)||patch.price_rial<=0)return res.status(400).json({error:'قیمت نامعتبر است.'});}
  const {data,error}=await db.from('products').update(patch).eq('id',req.params.id).select().single();
  if(error)return res.status(500).json({error:'ویرایش ناموفق بود.'});res.json({ok:true,product:data});
}));
app.delete('/api/admin/products/:id',admin,requireDb,asyncRoute(async(req,res)=>{
  const {error}=await db.from('products').update({active:false}).eq('id',req.params.id);
  if(error)return res.status(500).json({error:'غیرفعال‌سازی انجام نشد.'});res.json({ok:true});
}));
app.get('/api/admin/orders',admin,requireDb,asyncRoute(async(req,res)=>{
  const {data,error}=await db.from('orders').select('id,user_id,product_title,amount_rial,status,created_at,paid_at').order('created_at',{ascending:false}).limit(100);
  if(error)return res.status(500).json({error:'دریافت سفارش‌ها انجام نشد.'});res.json(data||[]);
}));
app.get('/api/admin/users',admin,requireDb,asyncRoute(async(req,res)=>{
  const {data,error}=await db.from('users').select('id,username,role,created_at').order('created_at',{ascending:false}).limit(200);
  if(error)return res.status(500).json({error:'دریافت کاربران انجام نشد.'});res.json(data||[]);
}));

app.get('/api/messages',auth,requireDb,asyncRoute(async(req,res)=>{
  let query=db.from('messages').select('id,user_id,sender_role,body,created_at').order('created_at',{ascending:true}).limit(150);
  if(req.user.role!=='admin') query=query.eq('user_id',req.user.id);
  const {data,error}=await query;
  if(error)return res.status(500).json({error:'دریافت پیام‌ها ناموفق بود.'});
  res.json(data||[]);
}));
app.post('/api/messages',auth,requireDb,asyncRoute(async(req,res)=>{
  const body=String(req.body?.body||'').trim();
  if(!body||body.length>2000)return res.status(400).json({error:'پیام باید بین ۱ تا ۲۰۰۰ کاراکتر باشد.'});
  const row={user_id:req.user.role==='admin'&&req.body?.user_id?String(req.body.user_id):req.user.id,
    sender_role:req.user.role==='admin'?'admin':'customer',body};
  const {data,error}=await db.from('messages').insert(row).select().single();
  if(error)return res.status(500).json({error:'ارسال پیام انجام نشد.'});
  res.json({ok:true,message:data});
}));

async function requestZarinpal(order){
  const base=SANDBOX?'https://sandbox.zarinpal.com/pg/v4/payment':'https://api.zarinpal.com/pg/v4/payment';
  const response=await fetch(`${base}/request.json`,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},
    body:JSON.stringify({merchant_id:MERCHANT_ID,amount:Number(order.amount_rial),
      callback_url:`${SITE_URL}/api/payment/zarinpal/callback?order=${encodeURIComponent(order.id)}`,
      description:`خرید ${order.product_title} از KAREN WEB`})});
  const body=await response.json();
  if(!response.ok||body?.data?.code!==100||!body?.data?.authority)throw new Error('Payment request rejected');
  return body.data.authority;
}
app.post('/api/checkout',auth,requireDb,asyncRoute(async(req,res)=>{
  const productId=String(req.body?.product_id||'');
  const {data:product,error:pe}=await db.from('products').select('id,title,price_rial,active').eq('id',productId).eq('active',true).single();
  if(pe||!product)return res.status(404).json({error:'قالب پیدا نشد.'});
  const {data:order,error:oe}=await db.from('orders').insert({
    user_id:req.user.id,product_id:product.id,product_title:product.title,amount_rial:product.price_rial,status:'pending'
  }).select().single();
  if(oe)return res.status(500).json({error:'ثبت سفارش انجام نشد.'});
  if(PAYMENT_MODE!=='zarinpal'||!MERCHANT_ID||!SITE_URL.startsWith('https://'))
    return res.status(503).json({error:'سفارش ثبت شد؛ اما درگاه هنوز توسط مدیر فعال نشده است.',order_id:order.id});
  try{
    const authority=await requestZarinpal(order);
    const {error}=await db.from('orders').update({payment_authority:authority}).eq('id',order.id);
    if(error)throw error;
    res.json({ok:true,redirect_url:`${SANDBOX?'https://sandbox.zarinpal.com':'https://www.zarinpal.com'}/pg/StartPay/${authority}`});
  }catch(e){console.error('checkout payment error',e.message);res.status(502).json({error:'اتصال به درگاه پرداخت ناموفق بود.'});}
}));
app.get('/api/payment/zarinpal/callback',requireDb,asyncRoute(async(req,res)=>{
  const orderId=String(req.query.order||''),authority=String(req.query.Authority||''),status=String(req.query.Status||'');
  if(!orderId||!authority||status!=='OK'||!MERCHANT_ID)return res.redirect('/payment-result.html?result=failed');
  const {data:order,error}=await db.from('orders').select('*').eq('id',orderId).single();
  if(error||!order||order.status==='failed'||(order.payment_authority&&order.payment_authority!==authority))
    return res.redirect('/payment-result.html?result=failed');
  if(order.status==='paid')return res.redirect(`/payment-result.html?result=success&order=${encodeURIComponent(order.id)}`);
  const base=SANDBOX?'https://sandbox.zarinpal.com/pg/v4/payment':'https://api.zarinpal.com/pg/v4/payment';
  const vr=await fetch(`${base}/verify.json`,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},
    body:JSON.stringify({merchant_id:MERCHANT_ID,amount:Number(order.amount_rial),authority})});
  const result=await vr.json(),code=result?.data?.code;
  if(!vr.ok||![100,101].includes(code)){
    await db.from('orders').update({status:'failed'}).eq('id',order.id).eq('status','pending');
    return res.redirect('/payment-result.html?result=failed');
  }
  await db.from('orders').update({status:'paid',payment_ref_id:String(result.data.ref_id||''),paid_at:new Date().toISOString()})
    .eq('id',order.id).eq('status','pending');
  res.redirect(`/payment-result.html?result=success&order=${encodeURIComponent(order.id)}`);
}));
app.get('/api/download/:orderId',auth,requireDb,asyncRoute(async(req,res)=>{
  const {data:order,error}=await db.from('orders').select('id,user_id,product_id,status').eq('id',req.params.orderId).single();
  if(error||!order||order.status!=='paid'||(req.user.role!=='admin'&&order.user_id!==req.user.id))
    return res.status(403).send('این سفارش برای حساب شما پرداخت‌شده نیست.');
  const {data:product,error:pe}=await db.from('products').select('storage_path').eq('id',order.product_id).single();
  if(pe||!product?.storage_path)return res.status(404).send('فایل قالب هنوز بارگذاری نشده است.');
  const {data,error:se}=await db.storage.from(BUCKET).createSignedUrl(product.storage_path,300,{download:true});
  if(se||!data?.signedUrl)return res.status(500).send('ساخت لینک دانلود ناموفق بود.');
  res.redirect(data.signedUrl);
}));
app.get('/api/order-status/:id',auth,requireDb,asyncRoute(async(req,res)=>{
  const {data,error}=await db.from('orders').select('id,product_title,status,user_id').eq('id',req.params.id).single();
  if(error||!data||(req.user.role!=='admin'&&data.user_id!==req.user.id))return res.status(404).json({error:'سفارش پیدا نشد.'});
  res.json({id:data.id,product_title:data.product_title,status:data.status});
}));

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'خطای داخلی سرور رخ داد.'});});
ensureOwnerAccount().then(()=>app.listen(PORT,()=>console.log(`KAREN WEB V2 listening on ${PORT}`)))
  .catch(err=>{console.error('Startup failed:',err.message);process.exit(1);});
