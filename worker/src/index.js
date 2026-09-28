const encoder = new TextEncoder();
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", ...headers } });
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();

function cors(env) {
  return {
    "access-control-allow-origin": env.FRONTEND_ORIGIN,
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
    vary: "Origin"
  };
}
function withCors(res, env) {
  const h = new Headers(res.headers); for (const [k,v] of Object.entries(cors(env))) h.set(k,v);
  return new Response(res.body, { status: res.status, headers: h });
}
function cookie(name, value, maxAge) { return `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`; }
function getCookie(req, name) { const m = req.headers.get("Cookie")?.match(new RegExp(`(?:^|; )${name}=([^;]+)`)); return m ? decodeURIComponent(m[1]) : null; }
async function digest(text) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)))].map(x=>x.toString(16).padStart(2,"0")).join(""); }
async function hashPassword(password, salt = crypto.randomUUID()) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", salt:encoder.encode(salt), iterations:210000, hash:"SHA-256" }, key, 256);
  return `pbkdf2$210000$${salt}$${btoa(String.fromCharCode(...new Uint8Array(bits)))}`;
}
async function verifyPassword(password, stored) {
  const [, iterations, salt, b64] = stored.split("$");
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", salt:encoder.encode(salt), iterations:Number(iterations), hash:"SHA-256" }, key, 256);
  const got = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return got === b64;
}
async function currentUser(req, env) {
  const sid = getCookie(req, "ventro_session"); if (!sid) return null;
  const row = await env.DB.prepare("SELECT u.id,u.email,u.role,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>? ").bind(sid, now()).first();
  return row || null;
}
async function requireUser(req, env) { const u = await currentUser(req, env); if (!u) throw new Error("UNAUTHENTICATED"); return u; }
async function requireAdmin(req, env) { const u = await requireUser(req, env); if (u.role !== "admin") throw new Error("FORBIDDEN"); return u; }
async function stripe(env, path, params, method="POST") {
  const body = params instanceof URLSearchParams ? params : new URLSearchParams(params);
  const r = await fetch(`https://api.stripe.com/v1/${path}`, { method, headers:{ Authorization:`Bearer ${env.STRIPE_SECRET_KEY}`, "content-type":"application/x-www-form-urlencoded" }, body: method === "GET" ? undefined : body });
  const text = await r.text(); let data; try { data=JSON.parse(text); } catch { data={raw:text}; }
  if (!r.ok) throw new Error(data?.error?.message || "Stripe request failed"); return data;
}
async function stripeSignatureValid(req, payload, secret) {
  const header = req.headers.get("Stripe-Signature"); if (!header) return false;
  const parts = Object.fromEntries(header.split(",").map(x=>x.split("=")));
  const timestamp = Number(parts.t); if (!timestamp || Math.abs(Date.now()/1000-timestamp)>300 || !parts.v1) return false;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), {name:"HMAC",hash:"SHA-256"}, false,["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(`${timestamp}.${payload}`));
  const hex = [...new Uint8Array(sig)].map(x=>x.toString(16).padStart(2,"0")).join("");
  return hex === parts.v1;
}
async function sendEmail(env, to, subject, html) {
  if (!env.RESEND_API_KEY) throw new Error("RESEND_API_KEY is not configured");
  const r = await fetch("https://api.resend.com/emails", { method:"POST", headers:{ Authorization:`Bearer ${env.RESEND_API_KEY}`, "content-type":"application/json" }, body:JSON.stringify({from:env.EMAIL_FROM || "Ventro Bank <onboarding@resend.dev>",to:[to],subject,html}) });
  if (!r.ok) throw new Error(`Email provider error: ${r.status}`);
}
async function route(req, env) {
  const url = new URL(req.url); const p = url.pathname.replace(/\/$/,"") || "/";
  if (req.method === "OPTIONS") return new Response(null,{status:204,headers:cors(env)});
  if (p === "/health") return json({ok:true});

  if (p === "/auth/signup" && req.method === "POST") {
    const {email,password}=await req.json(); const e=String(email||"").trim().toLowerCase();
    if(!/^\S+@\S+\.\S+$/.test(e)||typeof password!=="string"||password.length<10) return json({error:"Use a valid email and a password of at least 10 characters."},400);
    const exists=await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(e).first(); if(exists) return json({error:"An account already exists for this email."},409);
    const userId=id(), t=now(), role=e===env.ADMIN_EMAIL.toLowerCase()?"admin":"user"; const ph=await hashPassword(password);
    await env.DB.prepare("INSERT INTO users(id,email,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?,?)").bind(userId,e,ph,role,t,t).run();
    const sid=id(); await env.DB.prepare("INSERT INTO sessions(id,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(sid,userId,new Date(Date.now()+30*864e5).toISOString(),t).run();
    return json({user:{id:userId,email:e,role}},201,{"set-cookie":cookie("ventro_session",sid,30*86400)});
  }
  if (p === "/auth/login" && req.method === "POST") {
    const {email,password}=await req.json(); const e=String(email||"").trim().toLowerCase(); const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(e).first();
    if(!u || !(await verifyPassword(String(password||""),u.password_hash))) return json({error:"Invalid email or password."},401);
    if(e===env.ADMIN_EMAIL.toLowerCase() && u.role!=="admin") await env.DB.prepare("UPDATE users SET role='admin',updated_at=? WHERE id=?").bind(now(),u.id).run();
    const sid=id(); await env.DB.prepare("INSERT INTO sessions(id,user_id,expires_at,created_at) VALUES(?,?,?,?)").bind(sid,u.id,new Date(Date.now()+30*864e5).toISOString(),now()).run();
    return json({user:{id:u.id,email:u.email,role:e===env.ADMIN_EMAIL.toLowerCase()?"admin":u.role}},{"set-cookie":cookie("ventro_session",sid,30*86400)});
  }
  if (p === "/auth/logout" && req.method === "POST") { const sid=getCookie(req,"ventro_session"); if(sid) await env.DB.prepare("DELETE FROM sessions WHERE id=?").bind(sid).run(); return json({ok:true},{"set-cookie":cookie("ventro_session","",0)}); }
  if (p === "/auth/me" && req.method === "GET") { const u=await currentUser(req,env); return json({user:u}); }
  if (p === "/auth/forgot" && req.method === "POST") {
    const {email}=await req.json(); const u=await env.DB.prepare("SELECT id,email FROM users WHERE email=?").bind(String(email||"").trim().toLowerCase()).first();
    if(u){const token=crypto.randomUUID()+crypto.randomUUID(), hash=await digest(token), t=now(); await env.DB.prepare("INSERT INTO password_resets(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)").bind(id(),u.id,hash,new Date(Date.now()+30*60e3).toISOString(),t).run(); const reset=`${env.FRONTEND_ORIGIN}/reset-password?token=${encodeURIComponent(token)}`; await sendEmail(env,u.email,"Reset your Ventro Bank password",`<p>Reset your Ventro Bank password.</p><p><a href="${reset}">Reset password</a></p><p>This link expires in 30 minutes.</p>`);}
    return json({ok:true});
  }
  if (p === "/auth/reset" && req.method === "POST") {
    const {token,password}=await req.json(); if(typeof password!=="string"||password.length<10) return json({error:"Password must be at least 10 characters."},400);
    const hash=await digest(String(token||"")); const r=await env.DB.prepare("SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL AND expires_at>? ").bind(hash,now()).first(); if(!r) return json({error:"Invalid or expired reset link."},400);
    await env.DB.prepare("UPDATE users SET password_hash=?,updated_at=? WHERE id=?").bind(await hashPassword(password),now(),r.user_id).run(); await env.DB.prepare("UPDATE password_resets SET used_at=? WHERE id=?").bind(now(),r.id).run(); await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(r.user_id).run(); return json({ok:true});
  }

  if (p === "/store" && req.method === "GET") return json({product:"Ventro Bank",amount:1000,currency:"cad",type:"one_time",configured:Boolean(env.STRIPE_PRICE_ID && !env.STRIPE_PRICE_ID.startsWith("REPLACE"))});
  if (p === "/stripe/checkout" && req.method === "POST") {
    const u=await requireUser(req,env); if(!env.STRIPE_PRICE_ID||env.STRIPE_PRICE_ID.startsWith("REPLACE")) return json({error:"Stripe purchase is not configured yet."},503);
    const origin=env.FRONTEND_ORIGIN; const s=await stripe(env,"checkout/sessions",{mode:"payment",line_items:{0:{price:env.STRIPE_PRICE_ID,quantity:1}},"line_items[0][price]":env.STRIPE_PRICE_ID,"line_items[0][quantity]":"1",customer_email:u.email,client_reference_id:u.id,success_url:`${origin}/account?purchase=success`,cancel_url:`${origin}/store?purchase=cancelled`,"metadata[user_id]":u.id});
    return json({url:s.url});
  }
  if (p === "/subscription/checkout" && req.method === "POST") {
    const u=await requireUser(req,env); if(!env.STRIPE_SUBSCRIPTION_PRICE_ID||env.STRIPE_SUBSCRIPTION_PRICE_ID.startsWith("REPLACE")) return json({error:"Update subscription is not configured yet."},503);
    const s=await stripe(env,"checkout/sessions",{mode:"subscription","line_items[0][price]":env.STRIPE_SUBSCRIPTION_PRICE_ID,"line_items[0][quantity]":"1",customer_email:u.email,client_reference_id:u.id,success_url:`${env.FRONTEND_ORIGIN}/subscription?status=active`,cancel_url:`${env.FRONTEND_ORIGIN}/subscription?status=cancelled`,"metadata[user_id]":u.id}); return json({url:s.url});
  }
  if (p === "/subscription/portal" && req.method === "POST") {
    const u=await requireUser(req,env); const sub=await env.DB.prepare("SELECT stripe_customer_id FROM subscriptions WHERE user_id=? ORDER BY updated_at DESC LIMIT 1").bind(u.id).first(); if(!sub?.stripe_customer_id) return json({error:"No Stripe customer is linked to this account."},404);
    const s=await stripe(env,"billing_portal/sessions",{customer:sub.stripe_customer_id,return_url:`${env.FRONTEND_ORIGIN}/subscription`}); return json({url:s.url});
  }
  if (p === "/account" && req.method === "GET") {
    const u=await requireUser(req,env); const purchase=await env.DB.prepare("SELECT * FROM purchases WHERE user_id=? AND status='paid' ORDER BY purchased_at DESC LIMIT 1").bind(u.id).first(); const sub=await env.DB.prepare("SELECT status,current_period_end FROM subscriptions WHERE user_id=? ORDER BY updated_at DESC LIMIT 1").bind(u.id).first(); const latest=await env.DB.prepare("SELECT version,release_date,title FROM releases WHERE published=1 ORDER BY release_date DESC LIMIT 1").first(); return json({user:u,purchase,subscription:sub,latestRelease:latest});
  }
  if (p === "/releases" && req.method === "GET") { const u=await currentUser(req,env); const purchased=u?Boolean(await env.DB.prepare("SELECT id FROM purchases WHERE user_id=? AND status='paid' LIMIT 1").bind(u.id).first()):false; const rows=await env.DB.prepare("SELECT id,version,title,release_date,release_notes,description,published FROM releases WHERE published=1 ORDER BY release_date DESC").all(); return json({releases:rows.results,purchased}); }
  if (p.startsWith("/download/") && req.method === "GET") {
    const u=await requireUser(req,env); const paid=await env.DB.prepare("SELECT id FROM purchases WHERE user_id=? AND status='paid' LIMIT 1").bind(u.id).first(); if(!paid) return json({error:"Purchase required."},403); const release=await env.DB.prepare("SELECT * FROM releases WHERE id=? AND published=1").bind(p.split("/")[2]).first(); if(!release) return json({error:"Release not found."},404); const object=await env.APK_BUCKET.get(release.object_key); if(!object) return json({error:"Release file is unavailable."},404); const headers=new Headers({"content-type":"application/vnd.android.package-archive","content-disposition:`attachment; filename="Ventro-Bank-${release.version}.apk"`}); object.writeHttpMetadata(headers); headers.set("cache-control","private, no-store"); return new Response(object.body,{headers});
  }
  if (p === "/updates" && req.method === "GET") { const rows=await env.DB.prepare("SELECT id,title,version,published_at,description,release_notes,image_url,release_id FROM updates WHERE published=1 ORDER BY published_at DESC").all(); return json({updates:rows.results}); }

  if (p === "/admin/overview" && req.method === "GET") { await requireAdmin(req,env); const q=async s=>(await env.DB.prepare(s).first())?.n||0; return json({users:await q("SELECT COUNT(*) n FROM users"),purchases:await q("SELECT COUNT(*) n FROM purchases WHERE status='paid'"),activeSubscriptions:await q("SELECT COUNT(*) n FROM subscriptions WHERE status IN ('active','trialing')"),canceledSubscriptions:await q("SELECT COUNT(*) n FROM subscriptions WHERE status IN ('canceled','unpaid','past_due')"),latest:await env.DB.prepare("SELECT version,title FROM releases WHERE published=1 ORDER BY release_date DESC LIMIT 1").first()}); }
  if (p === "/admin/releases" && req.method === "POST") {
    const admin=await requireAdmin(req,env); const form=await req.formData(); const file=form.get("apk"); const version=String(form.get("version")||"").trim(), title=String(form.get("title")||"").trim(), notes=String(form.get("release_notes")||"").trim(), description=String(form.get("description")||"").trim(); if(!(file instanceof File)||!version||!title||!notes) return json({error:"Version, title, release notes, and an APK are required."},400); const key=`releases/${version}/${crypto.randomUUID()}.apk`; await env.APK_BUCKET.put(key,file.stream(),{httpMetadata:{contentType:"application/vnd.android.package-archive"}}); const rid=id(), t=now(); await env.DB.prepare("INSERT INTO releases(id,version,title,release_date,release_notes,description,object_key,published,created_at) VALUES(?,?,?,?,?,?,?,1,?)").bind(rid,version,title,t,notes,description,key,t).run(); return json({ok:true,releaseId:rid,by:admin.email},201);
  }
  if (p === "/admin/updates" && req.method === "POST") {
    await requireAdmin(req,env); const b=await req.json(); const uid=id(), t=now(); await env.DB.prepare("INSERT INTO updates(id,title,version,published_at,description,release_notes,image_url,release_id,published) VALUES(?,?,?,?,?,?,?,?,1)").bind(uid,b.title,b.version,t,b.description||"",b.release_notes||"",b.image_url||null,b.release_id||null).run();
    const users=await env.DB.prepare("SELECT u.id,u.email FROM users u JOIN subscriptions s ON s.user_id=u.id WHERE s.status IN ('active','trialing') GROUP BY u.id").all(); for(const user of users.results){ try{ await sendEmail(env,user.email,`Ventro Bank ${b.version}: ${b.title}`,`<h2>${b.title}</h2><p>Version ${b.version}</p><p>${b.description||""}</p><p><a href="${env.FRONTEND_ORIGIN}/updates">View Update</a></p>`); await env.DB.prepare("INSERT OR IGNORE INTO email_events(id,update_id,user_id,sent_at) VALUES(?,?,?,?)").bind(id(),uid,user.id,t).run(); }catch{} }
    return json({ok:true,id:uid},201);
  }

  if (p === "/stripe/webhook" && req.method === "POST") {
    const raw=await req.text(); if(!(await stripeSignatureValid(req,raw,env.STRIPE_WEBHOOK_SECRET))) return json({error:"Invalid signature."},400); const event=JSON.parse(raw); const o=event.data?.object;
    if(event.type==="checkout.session.completed" && o.payment_status==="paid") { const uid=o.metadata?.user_id||o.client_reference_id; if(uid){ await env.DB.prepare("INSERT OR IGNORE INTO purchases(id,user_id,stripe_session_id,stripe_payment_intent_id,amount,currency,status,purchased_at) VALUES(?,?,?,?,?,?,?,?)").bind(id(),uid,o.id,o.payment_intent||null,o.amount_total||1000,o.currency||"cad","paid",now()).run(); } }
    if(event.type.startsWith("customer.subscription.")){ const uid=o.metadata?.user_id; if(uid){ await env.DB.prepare("INSERT INTO subscriptions(id,user_id,stripe_customer_id,stripe_subscription_id,status,current_period_end,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(stripe_subscription_id) DO UPDATE SET status=excluded.status,current_period_end=excluded.current_period_end,updated_at=excluded.updated_at").bind(id(),uid,o.customer,o.id,o.status,o.current_period_end?new Date(o.current_period_end*1000).toISOString():null,now()).run(); } }
    return json({received:true});
  }
  return json({error:"Not found"},404);
}
export default { async fetch(req,env){ try{return withCors(await route(req,env),env);}catch(e){const status=e.message==="UNAUTHENTICATED"?401:e.message==="FORBIDDEN"?403:500; return withCors(json({error:status===500?"Server error":e.message},status),env);} } };
