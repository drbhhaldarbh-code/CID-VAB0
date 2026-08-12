const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const path=require("path");
const app=express(), db=new Database("cid.db");
const backupDir=path.join(__dirname,"backups");
if(!fs.existsSync(backupDir))fs.mkdirSync(backupDir,{recursive:true});
function backupDb(){try{const stamp=new Date().toISOString().replace(/[:.]/g,"-");db.backup(path.join(backupDir,`cid-${stamp}.db`));}catch(e){console.error("Backup failed:",e.message)}}
backupDb(); setInterval(backupDb,6*60*60*1000);

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 name TEXT NOT NULL,
 rank TEXT NOT NULL,
 active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS audit_log(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER,
 action TEXT NOT NULL,
 target TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wanted(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 case_no TEXT, game_id TEXT, name TEXT, age TEXT, residence TEXT,
 status TEXT, priority TEXT, photo TEXT
);
CREATE TABLE IF NOT EXISTS private_info(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 wanted_id INTEGER, field TEXT, value TEXT,
 FOREIGN KEY(wanted_id) REFERENCES wanted(id)
);
CREATE TABLE IF NOT EXISTS messages(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL,
 recipient_id INTEGER NOT NULL,
 body TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin_notes(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL,
 body TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS announcements(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL,
 title TEXT NOT NULL,
 body TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const ranks={
"مدير":{manageMembers:true,manageWanted:true,manageTasks:true,manageRules:true,manageAnnouncements:true,archive:true,delete:true,addInfo:true},
"نائب":{manageMembers:true,manageWanted:true,manageTasks:true,manageRules:false,manageAnnouncements:false,archive:false,delete:true,addInfo:true},
"مارشال":{manageMembers:false,manageWanted:true,manageTasks:true,manageRules:false,manageAnnouncements:true,archive:false,delete:false,addInfo:false},
"جنرال":{manageMembers:false,manageWanted:true,manageTasks:true,manageRules:false,manageAnnouncements:false,archive:false,delete:false,addInfo:true},
"مشرف":{manageMembers:false,manageWanted:true,manageTasks:true,manageRules:false,manageAnnouncements:false,archive:false,delete:false,addInfo:false},
"عضو":{manageMembers:false,manageWanted:false,manageTasks:false,manageRules:false,manageAnnouncements:false,archive:false,delete:false,addInfo:true}
};

const count=db.prepare("SELECT COUNT(*) c FROM users").get().c;
if(!count){
 const hash=bcrypt.hashSync("ChangeMe123!",10);
 db.prepare("INSERT INTO users(username,password,name,rank) VALUES(?,?,?,?)").run("admin",hash,"مدير CID","مدير");
 db.prepare("INSERT INTO users(username,password,name,rank) VALUES(?,?,?,?)").run("deputy",bcrypt.hashSync("Deputy123!",10),"نائب CID","نائب");
 db.prepare("INSERT INTO users(username,password,name,rank) VALUES(?,?,?,?)").run("marshal",bcrypt.hashSync("Marshal123!",10),"مارشال CID","مارشال");
 db.prepare("INSERT INTO users(username,password,name,rank) VALUES(?,?,?,?)").run("general",bcrypt.hashSync("General123!",10),"جنرال CID","جنرال");
 db.prepare("INSERT INTO users(username,password,name,rank) VALUES(?,?,?,?)").run("member",bcrypt.hashSync("Member123!",10),"عضو CID","عضو");
}
app.use(express.json({limit:"2mb"}));
app.use(session({secret:"cid-madout2-change-this-in-production",resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax"}}));
app.use(express.static(path.join(__dirname,"public")));

function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:"غير مسجل الدخول"});next()}
function perm(p){return (req,res,next)=>{if(!req.session.user||!ranks[req.session.user.rank][p])return res.status(403).json({error:"لا تملك هذه الصلاحية"});next()}}

app.post("/api/login",(req,res)=>{
 const u=db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(req.body.username);
 if(!u||!bcrypt.compareSync(req.body.password,u.password))return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
 req.session.user={id:u.id,username:u.username,name:u.name,rank:u.rank};res.json(req.session.user);
});
app.post("/api/logout",auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",auth,(req,res)=>res.json(req.session.user));

app.get("/api/members",auth,(req,res)=>{
 res.json(db.prepare("SELECT id,username,name,rank,active FROM users ORDER BY id").all());
});
app.post("/api/members",auth,perm("manageMembers"),(req,res)=>{
 const {username,password,name,rank}=req.body;
 if(!username||!password||!name||!ranks[rank])return res.status(400).json({error:"بيانات ناقصة"});
 const info=db.prepare("INSERT INTO users(username,password,name,rank) VALUES(?,?,?,?)")
 .run(username,bcrypt.hashSync(password,10),name,rank);
 res.json({id:info.lastInsertRowid});
});

app.get("/api/wanted",auth,(req,res)=>{
 res.json(db.prepare("SELECT id,case_no,game_id,name,age,residence,status,priority,photo FROM wanted ORDER BY id DESC").all());
});
app.post("/api/wanted",auth,perm("manageWanted"),(req,res)=>{
 const x=req.body; const info=db.prepare(`INSERT INTO wanted(case_no,game_id,name,age,residence,status,priority,photo) VALUES(?,?,?,?,?,?,?,?)`)
 .run(x.case_no,x.game_id,x.name,x.age||"",x.residence||"",x.status||"تحقيق",x.priority||"متوسط",x.photo||"");
 res.json({id:info.lastInsertRowid});
});
app.post("/api/wanted/:id/private",auth,perm("archive"),(req,res)=>{
 const x=req.body;if(!x.field||!x.value)return res.status(400).json({error:"معلومة ناقصة"});
 db.prepare("INSERT INTO private_info(wanted_id,field,value) VALUES(?,?,?)").run(req.params.id,x.field,x.value);
 db.prepare("INSERT INTO audit_log(user_id,action,target) VALUES(?,?,?)").run(req.session.user.id,"إضافة معلومة خاصة",String(req.params.id));
 res.json({ok:true});
});
app.get("/api/archive",auth,perm("archive"),(req,res)=>{
 res.json(db.prepare("SELECT * FROM private_info ORDER BY id DESC").all());
});


app.get("/api/audit",auth,perm("archive"),(req,res)=>{
 res.json(db.prepare("SELECT * FROM audit_log ORDER BY id DESC").all());
});
app.all("/api/:collection/:id", (req,res,next)=>{
 if(req.method==="DELETE") return res.status(405).json({error:"الحذف معطل للحفاظ على ثبات السجلات"});
 next();
});

app.get("/api/users",auth,(req,res)=>res.json(db.prepare("SELECT id,name,username,rank FROM users WHERE active=1 ORDER BY name").all()));
app.get("/api/messages/:userId",auth,(req,res)=>{
 const uid=Number(req.params.userId);
 res.json(db.prepare(`SELECT m.*,u.name sender_name,u.rank sender_rank FROM messages m JOIN users u ON u.id=m.sender_id
 WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) ORDER BY m.id`)
 .all(req.session.user.id,uid,uid,req.session.user.id));
});
app.post("/api/messages",auth,(req,res)=>{
 const recipient=Number(req.body.recipient_id),body=String(req.body.body||"").trim();
 if(!recipient||!body)return res.status(400).json({error:"الرسالة ناقصة"});
 db.prepare("INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)").run(req.session.user.id,recipient,body);
 res.json({ok:true});
});
app.post("/api/admin-notes",auth,(req,res)=>{
 const body=String(req.body.body||"").trim(); if(!body)return res.status(400).json({error:"الرسالة فارغة"});
 db.prepare("INSERT INTO admin_notes(sender_id,body) VALUES(?,?)").run(req.session.user.id,body);res.json({ok:true});
});
app.get("/api/admin-notes",auth,perm("archive"),(req,res)=>res.json(db.prepare(`SELECT n.*,u.name sender_name,u.rank sender_rank FROM admin_notes n JOIN users u ON u.id=n.sender_id ORDER BY n.id DESC`).all()));


app.get("/api/announcements",auth,(req,res)=>{
 res.json(db.prepare(`SELECT a.*,u.name sender_name,u.rank sender_rank FROM announcements a JOIN users u ON u.id=a.sender_id ORDER BY a.id DESC`).all());
});
app.post("/api/announcements",auth,(req,res)=>{
 if(!ranks[req.session.user.rank].manageAnnouncements)return res.status(403).json({error:"لا تملك صلاحية إدارة الإعلانات"});
 const title=String(req.body.title||"").trim(),body=String(req.body.body||"").trim();
 if(!title||!body)return res.status(400).json({error:"بيانات الإعلان ناقصة"});
 db.prepare("INSERT INTO announcements(sender_id,title,body) VALUES(?,?,?)").run(req.session.user.id,title,body);res.json({ok:true});
});

app.get("/api/permissions",auth,(req,res)=>res.json(ranks[req.session.user.rank]));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("CID running on port "+(process.env.PORT||3000)));
