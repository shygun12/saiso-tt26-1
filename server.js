const express=require("express");
const cookieParser=require("cookie-parser");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const {Pool}=require("pg");
const fs=require("fs");
const path=require("path");

const app=express();
app.use(express.json({limit:"2mb"}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname,"public")));

const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:false});
const SECRET=process.env.JWT_SECRET||"change-this-secret";

async function db(q,p=[]){return (await pool.query(q,p)).rows}
async function init(){
 const schema=fs.readFileSync(path.join(__dirname,"db/schema.sql"),"utf8");
 await pool.query(schema);
 const n=(await pool.query("select count(*) from users")).rows[0].count;
 if(Number(n)===0){
  const u=process.env.ADMIN_USERNAME||"admin";
  const pw=process.env.ADMIN_PASSWORD||"123456";
  await pool.query("insert into users(username,password_hash,full_name,role) values($1,$2,$3,'admin')",[u,await bcrypt.hash(pw,12),"Quản trị viên"]);
 }
 await pool.query("insert into catalog(code,name,unit,fixed) values('CV00','Đã chuyển bản vẽ cho Phòng BT&GPMB','công trình',true) on conflict(code) do update set name=excluded.name,unit=excluded.unit,fixed=true");
 const tasks=[["CV01","Đo hiện trạng","thửa"],["CV02","Lập phiếu đo đạc","phiếu"],["CV03","Kiểm tra hồ sơ","hồ sơ"],["CV04","Kiểm kê tài sản","hộ"],["CV05","Xác định ranh","thửa"],["CV06","Hoàn thiện hồ sơ","hồ sơ"]];
 for(const t of tasks) await pool.query("insert into catalog(code,name,unit) values($1,$2,$3) on conflict(code) do nothing",t);
}
function token(u){return jwt.sign({id:u.id,role:u.role,name:u.full_name},SECRET,{expiresIn:"7d"})}
function auth(req,res,next){try{req.user=jwt.verify(req.cookies.bcddbt,SECRET);next()}catch{return res.status(401).json({error:"Chưa đăng nhập"})}}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Chỉ Admin"});next()}

app.post("/api/login",async(req,res)=>{const {username,password}=req.body;const r=await db("select * from users where username=$1 and active=true",[username]);if(!r[0]||!(await bcrypt.compare(password,r[0].password_hash)))return res.status(401).json({error:"Sai tài khoản hoặc mật khẩu"});res.cookie("bcddbt",token(r[0]),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000});res.json({id:r[0].id,username:r[0].username,name:r[0].full_name,role:r[0].role})});
app.post("/api/logout",(req,res)=>{res.clearCookie("bcddbt");res.json({ok:true})});
app.get("/api/me",auth,async(req,res)=>res.json(req.user));
app.get("/api/bootstrap",auth,async(req,res)=>{const [projects,users,catalog,reports]=await Promise.all([
db("select * from projects order by id desc"),
db("select id,username,full_name,role,active from users order by id"),
db("select id,code,name,unit,fixed,active from catalog where active=true order by fixed desc,id"),
db("select r.*,p.code project_code,p.name project_name,u.full_name person from reports r join projects p on p.id=r.project_id join users u on u.id=r.user_id order by r.report_date desc,r.report_time desc,r.id desc")
]);res.json({projects,users,catalog,reports})});
app.post("/api/users",auth,admin,async(req,res)=>{const {username,password,full_name,role="member"}=req.body;if(!username||!password||!full_name)return res.status(400).json({error:"Thiếu thông tin"});const r=await db("insert into users(username,password_hash,full_name,role) values($1,$2,$3,$4) returning id,username,full_name,role,active",[username,await bcrypt.hash(password,12),full_name,role]);res.json(r[0])});
app.post("/api/projects",auth,admin,async(req,res)=>{const {code,name,location="",expected_qty=0,status="Đang thực hiện"}=req.body;const r=await db("insert into projects(code,name,location,expected_qty,status) values($1,$2,$3,$4,$5) returning *",[code,name,location,expected_qty,status]);res.json(r[0])});
app.post("/api/catalog",auth,admin,async(req,res)=>{const {code,name,unit}=req.body;if(name==="Đã chuyển bản vẽ cho Phòng BT&GPMB")return res.status(400).json({error:"Công việc cố định không được thay đổi"});const r=await db("insert into catalog(code,name,unit) values($1,$2,$3) returning *",[code,name,unit]);res.json(r[0])});
app.put("/api/catalog/:id",auth,admin,async(req,res)=>{const c=(await db("select * from catalog where id=$1",[req.params.id]))[0];if(!c||c.fixed)return res.status(400).json({error:"Công việc cố định không được thay đổi"});const r=await db("update catalog set name=$1,unit=$2 where id=$3 returning *",[req.body.name,req.body.unit,c.id]);res.json(r[0])});
app.post("/api/reports",auth,async(req,res)=>{const {project_id,person_id,items=[]}=req.body;if(req.user.role!=="admin"&&person_id&&Number(person_id)!==Number(req.user.id))return res.status(403).json({error:"Thành viên chỉ được gửi báo cáo của mình"});const uid=person_id||req.user.id;const out=[];const client=await pool.connect();try{await client.query("begin");for(const x of items){const qty=Number(x.qty||0),completed=Number(x.completed||0);if(qty<=0||completed>qty)throw new Error("Khối lượng không hợp lệ");const c=(await client.query("select id,name,unit from catalog where id=$1 and active=true",[x.task_id])).rows[0];if(!c)throw new Error("Công việc không tồn tại");const r=(await client.query("insert into reports(project_id,user_id,task_id,task_name,qty,completed,unit,note,review,direction,status,change_type) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'locked','new') returning *",[project_id,uid,c.id,c.name,qty,completed,c.unit,x.note||"",x.review||"",x.direction||""])).rows[0];out.push(r)}await client.query("commit");res.json(out)}catch(e){await client.query("rollback");res.status(400).json({error:e.message})}finally{client.release()}});
app.post("/api/reports/:id/request-edit",auth,async(req,res)=>{const r=(await db("select * from reports where id=$1",[req.params.id]))[0];if(!r)return res.status(404).json({error:"Không tìm thấy"});if(req.user.role!=="admin"&&r.user_id!==req.user.id)return res.status(403).json({error:"Không có quyền"});if(r.status!=="locked")return res.status(400).json({error:"Báo cáo không ở trạng thái khóa"});await db("update reports set status='edit_requested',edit_requested_at=now(),updated_at=now() where id=$1",[r.id]);const q=await db("insert into edit_requests(report_id,requester_id,reason) values($1,$2,$3) returning *",[r.id,req.user.id,req.body.reason||""]);res.json(q[0])});
app.get("/api/edit-requests",auth,admin,async(req,res)=>res.json(await db("select er.*,r.task_name,r.qty,r.unit,u.full_name requester from edit_requests er join reports r on r.id=er.report_id join users u on u.id=er.requester_id where er.status='pending' order by er.id desc")));
app.post("/api/edit-requests/:id/approve",auth,admin,async(req,res)=>{const q=(await db("select * from edit_requests where id=$1",[req.params.id]))[0];if(!q)return res.status(404).json({error:"Không tìm thấy"});await db("update edit_requests set status='approved',reviewed_at=now(),reviewer_id=$1 where id=$2",[req.user.id,q.id]);const r=await db("update reports set status='editing',edit_approved_at=now(),updated_at=now() where id=$1 returning *",[q.report_id]);res.json(r[0])});
app.put("/api/reports/:id",auth,async(req,res)=>{const r=(await db("select * from reports where id=$1",[req.params.id]))[0];if(!r)return res.status(404).json({error:"Không tìm thấy"});if(req.user.role!=="admin"&&!(r.status==="editing"&&r.user_id===req.user.id))return res.status(403).json({error:"Chưa được phép sửa"});const qty=Number(req.body.qty),completed=Number(req.body.completed);if(qty<=0||completed>qty)return res.status(400).json({error:"Khối lượng không hợp lệ"});const x=await db("update reports set qty=$1,completed=$2,note=$3,review=$4,direction=$5,status='locked',change_type='changed',updated_at=now() where id=$6 returning *",[qty,completed,req.body.note||"",req.body.review||"",req.body.direction||"",r.id]);await db("insert into audit_logs(actor_id,action,detail) values($1,'edit_report',$2)",[req.user.id,JSON.stringify({report:r.id,old_qty:r.qty,new_qty:qty})]);res.json(x[0])});
app.get("/api/summary",auth,async(req,res)=>{const projects=await db("select p.*,coalesce(sum(case when c.fixed=true then r.completed else 0 end),0) completed from projects p left join reports r on r.project_id=p.id left join catalog c on c.id=r.task_id group by p.id order by p.id");res.json(projects)});
app.get("/api/audit",auth,admin,async(req,res)=>res.json(await db("select a.*,u.full_name from audit_logs a left join users u on u.id=a.actor_id order by a.id desc limit 500")));
app.get("/{*splat}",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

init().then(()=>app.listen(process.env.PORT||3000,()=>console.log("BaoCaoCongViec V2.0 running"))).catch(e=>{console.error(e);process.exit(1)});
