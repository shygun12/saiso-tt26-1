const express=require("express");
const {rateLimit}=require("express-rate-limit");
const cookieParser=require("cookie-parser");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const {Pool}=require("pg");
const fs=require("fs");
const path=require("path");
const {Document,Packer,Paragraph,TextRun,Table,TableRow,TableCell,WidthType,AlignmentType,HeadingLevel}=require("docx");
const ExcelJS=require("exceljs");
const archiver=require("archiver");

const app=express();
app.use(express.json({limit:"2mb"}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname,"public")));
const loginLimiter=rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:"draft-8",legacyHeaders:false,message:{error:"Bạn đã đăng nhập sai hoặc thử quá nhiều lần. Vui lòng thử lại sau 15 phút."}});
const passwordLimiter=rateLimit({windowMs:15*60*1000,limit:5,standardHeaders:"draft-8",legacyHeaders:false,message:{error:"Bạn đã thử đổi mật khẩu quá nhiều lần. Vui lòng thử lại sau 15 phút."}});

const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:false});
const SECRET=process.env.JWT_SECRET||"change-this-secret";

async function db(q,p=[]){return (await pool.query(q,p)).rows}
async function init(){
 const schema=fs.readFileSync(path.join(__dirname,"db/schema.sql"),"utf8");
 await pool.query(schema);
 await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_root BOOLEAN NOT NULL DEFAULT FALSE");
 const n=(await pool.query("select count(*) from users")).rows[0].count;
 if(Number(n)===0 && !process.env.ROOT_ADMIN_USERNAME){
  const u=process.env.ADMIN_USERNAME||"admin";
  const pw=process.env.ADMIN_PASSWORD||"123456";
  await pool.query("insert into users(username,password_hash,full_name,role) values($1,$2,$3,'admin')",[u,await bcrypt.hash(pw,12),"Quản trị viên"]);
 }
 // Configure ROOT_ADMIN_USERNAME and ROOT_ADMIN_PASSWORD in Render environment variables.
 if(process.env.ROOT_ADMIN_USERNAME && process.env.ROOT_ADMIN_PASSWORD){
  const rootName=process.env.ROOT_ADMIN_USERNAME;
  const rootFullName=process.env.ROOT_ADMIN_FULL_NAME||"Võ Nhựt Hào";
  const rootHash=await bcrypt.hash(process.env.ROOT_ADMIN_PASSWORD,12);
  await pool.query("UPDATE users SET is_root=FALSE WHERE username<>$1",[rootName]);
  await pool.query("INSERT INTO users(username,password_hash,full_name,role,active,is_root) VALUES($1,$2,$3,'admin',TRUE,TRUE) ON CONFLICT(username) DO UPDATE SET password_hash=EXCLUDED.password_hash,full_name=EXCLUDED.full_name,role='admin',active=TRUE,is_root=TRUE",[rootName,rootHash,rootFullName]);
  if(rootName!=="admin") await pool.query("UPDATE users SET active=FALSE,is_root=FALSE WHERE username='admin'");
 }
 await pool.query("insert into catalog(code,name,unit,fixed) values('CV00','Đã chuyển bản vẽ cho Phòng BT&GPMB','công trình',true) on conflict(code) do update set name=excluded.name,unit=excluded.unit,fixed=true");
 const tasks=[["CV01","Đo hiện trạng","thửa"],["CV02","Lập phiếu đo đạc","phiếu"],["CV03","Kiểm tra hồ sơ","hồ sơ"],["CV04","Kiểm kê tài sản","hộ"],["CV05","Xác định ranh","thửa"],["CV06","Hoàn thiện hồ sơ","hồ sơ"]];
 for(const t of tasks) await pool.query("insert into catalog(code,name,unit) values($1,$2,$3) on conflict(code) do nothing",t);
}
function token(u){return jwt.sign({id:u.id,role:u.role,name:u.full_name,is_root:Boolean(u.is_root)},SECRET,{expiresIn:"7d"})}
function auth(req,res,next){try{req.user=jwt.verify(req.cookies.bcddbt,SECRET);next()}catch{return res.status(401).json({error:"Chưa đăng nhập"})}}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Chỉ Admin"});next()}

app.post("/api/login",loginLimiter,async(req,res)=>{const {username,password}=req.body;const r=await db("select * from users where username=$1 and active=true",[username]);if(!r[0]||!(await bcrypt.compare(password,r[0].password_hash)))return res.status(401).json({error:"Sai tài khoản hoặc mật khẩu"});res.cookie("bcddbt",token(r[0]),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000});res.json({id:r[0].id,username:r[0].username,name:r[0].full_name,role:r[0].role,is_root:Boolean(r[0].is_root)})});
app.post("/api/logout",(req,res)=>{res.clearCookie("bcddbt");res.json({ok:true})});
app.get("/api/me",auth,async(req,res)=>res.json(req.user));
app.post("/api/change-password",auth,passwordLimiter,async(req,res)=>{const current=String(req.body.current_password||""),next=String(req.body.new_password||""),confirm=String(req.body.confirm_password||"");if(!current||!next||!confirm)return res.status(400).json({error:"Vui lòng nhập đầy đủ các trường"});if(next.length<8)return res.status(400).json({error:"Mật khẩu mới phải có ít nhất 8 ký tự"});if(next!==confirm)return res.status(400).json({error:"Mật khẩu xác nhận không khớp"});if(current===next)return res.status(400).json({error:"Mật khẩu mới phải khác mật khẩu hiện tại"});const u=(await db("select id,password_hash from users where id=$1 and active=true",[req.user.id]))[0];if(!u||!(await bcrypt.compare(current,u.password_hash)))return res.status(400).json({error:"Mật khẩu hiện tại không chính xác"});await db("update users set password_hash=$1 where id=$2",[await bcrypt.hash(next,12),u.id]);await db("insert into audit_logs(actor_id,action,detail) values($1,'change_password',$2)",[req.user.id,JSON.stringify({changed_by_user:true})]);res.json({ok:true,message:"Đổi mật khẩu thành công"})});
app.get("/api/bootstrap",auth,async(req,res)=>{const projectSql=req.user.role==="admin"?"select p.*,coalesce(json_agg(json_build_object('id',u.id,'username',u.username,'full_name',u.full_name) order by u.full_name) filter (where u.id is not null),'[]') members from projects p left join project_members pm on pm.project_id=p.id left join users u on u.id=pm.user_id group by p.id order by p.id desc":"select p.*,coalesce(json_agg(json_build_object('id',u.id,'username',u.username,'full_name',u.full_name) order by u.full_name) filter (where u.id is not null),'[]') members from projects p join project_members me on me.project_id=p.id and me.user_id=$1 left join project_members pm on pm.project_id=p.id left join users u on u.id=pm.user_id group by p.id order by p.id desc";const reportSql=req.user.role==="admin"?"select r.*,p.code project_code,p.name project_name,u.full_name person from reports r join projects p on p.id=r.project_id join users u on u.id=r.user_id order by r.report_date desc,r.report_time desc,r.id desc":"select r.*,p.code project_code,p.name project_name,u.full_name person from reports r join projects p on p.id=r.project_id join users u on u.id=r.user_id where exists(select 1 from project_members pm where pm.project_id=r.project_id and pm.user_id=$1) order by r.report_date desc,r.report_time desc,r.id desc";const [projects,users,catalog,reports]=await Promise.all([
db(projectSql,req.user.role==="admin"?[]:[req.user.id]),
db("select id,username,full_name,role,active,is_root from users order by id"),
db("select id,code,name,unit,fixed,active from catalog where active=true order by fixed desc,id"),
db(reportSql,req.user.role==="admin"?[]:[req.user.id])
]);res.json({projects,users,catalog,reports})});
app.post("/api/users",auth,admin,async(req,res)=>{const {username,password,full_name,role="member"}=req.body;if(!username||!password||!full_name)return res.status(400).json({error:"Thiếu thông tin"});if(role==="admin"&&!req.user.is_root)return res.status(403).json({error:"Chỉ Admin gốc được tạo quản trị viên"});if(!["member","admin"].includes(role))return res.status(400).json({error:"Vai trò không hợp lệ"});const r=await db("insert into users(username,password_hash,full_name,role) values($1,$2,$3,$4) returning id,username,full_name,role,active",[username,await bcrypt.hash(password,12),full_name,role]);await db("insert into audit_logs(actor_id,action,detail) values($1,'create_user',$2)",[req.user.id,JSON.stringify({user_id:r[0].id,username,role})]);res.json({...r[0],is_root:false})});
app.put("/api/users/:id/role",auth,admin,async(req,res)=>{if(!req.user.is_root)return res.status(403).json({error:"Chỉ Admin gốc được thay đổi quyền quản trị"});const id=Number(req.params.id),role=req.body.role;if(!["member","admin"].includes(role))return res.status(400).json({error:"Vai trò không hợp lệ"});const target=(await db("select id,username,role,is_root from users where id=$1",[id]))[0];if(!target)return res.status(404).json({error:"Không tìm thấy người dùng"});if(target.is_root)return res.status(400).json({error:"Không thể thay đổi quyền Admin gốc"});const r=await db("update users set role=$1 where id=$2 returning id,username,full_name,role,active,is_root",[role,id]);if(role!=="admin")await db("delete from project_members where user_id=$1",[id]);await db("insert into audit_logs(actor_id,action,detail) values($1,'change_user_role',$2)",[req.user.id,JSON.stringify({user_id:id,username:target.username,old_role:target.role,new_role:role})]);res.json(r[0])});
app.put("/api/users/:id/status",auth,admin,async(req,res)=>{const id=Number(req.params.id),active=Boolean(req.body.active);const target=(await db("select id,username,role,is_root from users where id=$1",[id]))[0];if(!target)return res.status(404).json({error:"Không tìm thấy người dùng"});if(id===Number(req.user.id)&&!active)return res.status(400).json({error:"Không thể khóa tài khoản đang đăng nhập"});if(target.is_root&&!req.user.is_root)return res.status(403).json({error:"Chỉ Admin gốc mới có thể thay đổi trạng thái Admin gốc"});if(target.role==="admin"&&!req.user.is_root)return res.status(403).json({error:"Chỉ Admin gốc mới được khóa hoặc kích hoạt quản trị viên khác"});const r=await db("update users set active=$1 where id=$2 returning id,username,full_name,role,active,is_root",[active,id]);if(!active)await db("delete from project_members where user_id=$1",[id]);await db("insert into audit_logs(actor_id,action,detail) values($1,'update_user_status',$2)",[req.user.id,JSON.stringify({user_id:id,username:target.username,active})]);res.json(r[0])});
app.post("/api/projects",auth,admin,async(req,res)=>{const {code,name,location="",expected_qty=0,status="Đang thực hiện",member_ids=[]}=req.body;if(!code||!name)return res.status(400).json({error:"Thiếu mã hoặc tên công trình"});const client=await pool.connect();try{await client.query("begin");const r=(await client.query("insert into projects(code,name,location,expected_qty,status) values($1,$2,$3,$4,$5) returning *",[code,name,location,Number(expected_qty||0),status])).rows[0];const ids=[...new Set((Array.isArray(member_ids)?member_ids:[]).map(Number).filter(Number.isInteger))];if(ids.length)await client.query("insert into project_members(project_id,user_id) select $1,id from users where id=any($2::int[]) and active=true and role<>'admin' on conflict do nothing",[r.id,ids]);await client.query("insert into audit_logs(actor_id,action,detail) values($1,'add_project',$2)",[req.user.id,JSON.stringify({project:r.id,member_ids:ids})]);await client.query("commit");res.json(r)}catch(e){await client.query("rollback");res.status(400).json({error:e.message})}finally{client.release()}});
app.put("/api/projects/:id",auth,admin,async(req,res)=>{const p=(await db("select * from projects where id=$1",[req.params.id]))[0];if(!p)return res.status(404).json({error:"Không tìm thấy công trình"});const {code,name,location="",expected_qty=0,status="Đang thực hiện"}=req.body;if(!code||!name)return res.status(400).json({error:"Thiếu mã hoặc tên công trình"});const r=await db("update projects set code=$1,name=$2,location=$3,expected_qty=$4,status=$5 where id=$6 returning *",[code,name,location,Number(expected_qty||0),status,p.id]);await db("insert into audit_logs(actor_id,action,detail) values($1,'edit_project',$2)",[req.user.id,JSON.stringify({project:p.id,old:{code:p.code,name:p.name,location:p.location,expected_qty:p.expected_qty,status:p.status},new:r[0]})]);res.json(r[0])});
app.get("/api/projects/:id/members",auth,admin,async(req,res)=>{const rows=await db("select u.id,u.username,u.full_name,u.role,u.active from project_members pm join users u on u.id=pm.user_id where pm.project_id=$1 order by u.full_name",[req.params.id]);res.json(rows)});
app.put("/api/projects/:id/members",auth,admin,async(req,res)=>{const projectId=Number(req.params.id),ids=[...new Set((Array.isArray(req.body.member_ids)?req.body.member_ids:[]).map(Number).filter(Number.isInteger))];const p=(await db("select id from projects where id=$1",[projectId]))[0];if(!p)return res.status(404).json({error:"Không tìm thấy công trình"});const client=await pool.connect();try{await client.query("begin");const before=(await client.query("select user_id from project_members where project_id=$1 order by user_id",[projectId])).rows.map(x=>x.user_id);await client.query("delete from project_members where project_id=$1",[projectId]);if(ids.length)await client.query("insert into project_members(project_id,user_id) select $1,id from users where id=any($2::int[]) and active=true and role<>'admin' on conflict do nothing",[projectId,ids]);const after=(await client.query("select user_id from project_members where project_id=$1 order by user_id",[projectId])).rows.map(x=>x.user_id);await client.query("insert into audit_logs(actor_id,action,detail) values($1,'update_project_members',$2)",[req.user.id,JSON.stringify({project:projectId,before,after})]);await client.query("commit");res.json({ok:true,member_ids:after})}catch(e){await client.query("rollback");res.status(400).json({error:e.message})}finally{client.release()}});
app.post("/api/catalog",auth,admin,async(req,res)=>{const {code,name,unit}=req.body;if(name==="Đã chuyển bản vẽ cho Phòng BT&GPMB")return res.status(400).json({error:"Công việc cố định không được thay đổi"});const r=await db("insert into catalog(code,name,unit) values($1,$2,$3) returning *",[code,name,unit]);res.json(r[0])});
app.put("/api/catalog/:id",auth,admin,async(req,res)=>{const c=(await db("select * from catalog where id=$1 and active=true",[req.params.id]))[0];if(!c)return res.status(404).json({error:"Không tìm thấy công việc"});const name=String(req.body.name||"").trim(),unit=String(req.body.unit||"").trim(),fixed=Boolean(req.body.fixed);if(!name||!unit)return res.status(400).json({error:"Vui lòng nhập tên công việc và đơn vị"});const r=await db("update catalog set name=$1,unit=$2,fixed=$3 where id=$4 returning *",[name,unit,fixed,c.id]);if(name!==c.name)await db("update reports set task_name=$1 where task_id=$2",[name,c.id]);await db("insert into audit_logs(actor_id,action,detail) values($1,$2,$3)",[req.user.id,c.fixed!==fixed?(fixed?"fix_catalog_task":"unfix_catalog_task"):"edit_catalog_task",JSON.stringify({catalog_id:c.id,code:c.code,before:{name:c.name,unit:c.unit,fixed:c.fixed},after:{name,unit,fixed},historical_reports_unchanged:true})]);res.json(r[0])});
app.delete("/api/catalog/:id",auth,admin,async(req,res)=>{const c=(await db("select * from catalog where id=$1 and active=true",[req.params.id]))[0];if(!c)return res.status(404).json({error:"Không tìm thấy công việc"});await db("update catalog set active=false where id=$1",[c.id]);await db("insert into audit_logs(actor_id,action,detail) values($1,'delete_catalog_task',$2)",[req.user.id,JSON.stringify({catalog_id:c.id,code:c.code,name:c.name,fixed:c.fixed,detail:"Ẩn khỏi danh mục; giữ nguyên báo cáo cũ"})]);res.json({ok:true})});
app.post("/api/reports",auth,async(req,res)=>{const {project_id,person_id,items=[]}=req.body;const uid=person_id||req.user.id;if(req.user.role!=="admin"&&Number(uid)!==Number(req.user.id))return res.status(403).json({error:"Thành viên chỉ được gửi báo cáo của mình"});const memberOk=(await db("select exists(select 1 from project_members where project_id=$1 and user_id=$2) ok",[project_id,uid]))[0]?.ok;if(!memberOk&&req.user.role!=="admin")return res.status(403).json({error:"Người thực hiện chưa được phân công vào công trình"});if(req.user.role==="admin"&&person_id&&!memberOk)return res.status(400).json({error:"Người thực hiện chưa được phân công vào công trình"});const out=[];const client=await pool.connect();try{await client.query("begin");for(const x of items){const qty=Number(x.qty||0),completed=Number(x.completed||0);if(qty<=0||completed>qty)throw new Error("Khối lượng không hợp lệ");const c=(await client.query("select id,name,unit from catalog where id=$1 and active=true",[x.task_id])).rows[0];if(!c)throw new Error("Công việc không tồn tại");const r=(await client.query("insert into reports(project_id,user_id,task_id,task_name,qty,completed,unit,note,review,direction,status,change_type) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'locked','new') returning *",[project_id,uid,c.id,c.name,qty,completed,c.unit,x.note||"",x.review||"",x.direction||""])).rows[0];out.push(r)}await client.query("commit");res.json(out)}catch(e){await client.query("rollback");res.status(400).json({error:e.message})}finally{client.release()}});
app.post("/api/reports/:id/request-edit",auth,async(req,res)=>{const r=(await db("select * from reports where id=$1",[req.params.id]))[0];if(!r)return res.status(404).json({error:"Không tìm thấy báo cáo"});if(req.user.role!=="admin"&&Number(r.user_id)!==Number(req.user.id))return res.status(403).json({error:"Không có quyền"});if(r.status!=="locked")return res.status(400).json({error:"Báo cáo không ở trạng thái khóa"});const reason=String(req.body.reason||"").trim(),v=req.body.proposed_changes||{};const qty=Number(v.qty??r.qty),completed=Number(v.completed??r.completed);if(!reason)return res.status(400).json({error:"Vui lòng nhập lý do chỉnh sửa"});if(!Number.isFinite(qty)||qty<=0||!Number.isFinite(completed)||completed<0||completed>qty)return res.status(400).json({error:"Khối lượng chỉnh sửa không hợp lệ"});const changes={qty,completed,note:String(v.note??r.note??""),review:String(v.review??r.review??""),direction:String(v.direction??r.direction??"")};const client=await pool.connect();try{await client.query("begin");const q=(await client.query("insert into edit_requests(report_id,requester_id,reason,proposed_changes) values($1,$2,$3,$4::jsonb) returning *",[r.id,req.user.id,reason,JSON.stringify(changes)])).rows[0];await client.query("update reports set status='edit_requested',edit_requested_at=now(),updated_at=now() where id=$1",[r.id]);await client.query("commit");res.json(q)}catch(e){await client.query("rollback");res.status(400).json({error:e.message})}finally{client.release()}});
app.get("/api/edit-requests",auth,admin,async(req,res)=>res.json(await db("select er.*,r.project_id,r.report_date,r.report_time,r.task_name,r.qty,r.completed,r.unit,u.full_name requester,p.code project_code,p.name project_name from edit_requests er join reports r on r.id=er.report_id join users u on u.id=er.requester_id join projects p on p.id=r.project_id where er.status='pending' order by er.id desc")));
app.post("/api/edit-requests/:id/approve",auth,admin,async(req,res)=>{const q=(await db("select * from edit_requests where status='pending' and (id=$1 or report_id=$1) order by case when report_id=$1 then 0 else 1 end,id desc limit 1",[req.params.id]))[0];if(!q)return res.status(404).json({error:"Không tìm thấy yêu cầu duyệt đang chờ. Hãy tải lại trang."});const c=q.proposed_changes||{};const before=(await db("select * from reports where id=$1",[q.report_id]))[0];if(!before)return res.status(404).json({error:"Không tìm thấy báo cáo liên kết với yêu cầu"});const client=await pool.connect();try{await client.query("begin");const r=(await client.query("update reports set qty=$1,completed=$2,note=$3,review=$4,direction=$5,status='locked',change_type='changed',edit_approved_at=now(),updated_at=now() where id=$6 returning *",[Number(c.qty),Number(c.completed),c.note||"",c.review||"",c.direction||"",q.report_id])).rows[0];await client.query("update edit_requests set status='approved',reviewed_at=now(),reviewer_id=$1 where id=$2",[req.user.id,q.id]);await client.query("insert into audit_logs(actor_id,action,detail) values($1,'approve_edit_request',$2)",[req.user.id,JSON.stringify({request_id:q.id,report_id:q.report_id,reason:q.reason,project_id:r.project_id,task_name:r.task_name,old_values:{qty:before.qty,completed:before.completed,note:before.note,review:before.review,direction:before.direction},new_values:c,summary:"Admin đã duyệt và áp dụng nội dung chỉnh sửa"})]);await client.query("commit");res.json({ok:true,report:r,request_id:q.id})}catch(e){await client.query("rollback");res.status(400).json({error:e.message})}finally{client.release()}});
app.put("/api/reports/:id",auth,async(req,res)=>{const r=(await db("select * from reports where id=$1",[req.params.id]))[0];if(!r)return res.status(404).json({error:"Không tìm thấy"});if(req.user.role!=="admin"&&!(r.status==="editing"&&r.user_id===req.user.id))return res.status(403).json({error:"Chưa được phép sửa"});const qty=Number(req.body.qty),completed=Number(req.body.completed);if(qty<=0||completed>qty)return res.status(400).json({error:"Khối lượng không hợp lệ"});const x=await db("update reports set qty=$1,completed=$2,note=$3,review=$4,direction=$5,status='locked',change_type='changed',updated_at=now() where id=$6 returning *",[qty,completed,req.body.note||"",req.body.review||"",req.body.direction||"",r.id]);await db("insert into audit_logs(actor_id,action,detail) values($1,'edit_report',$2)",[req.user.id,JSON.stringify({report:r.id,old_qty:r.qty,new_qty:qty})]);res.json(x[0])});
app.get("/api/summary",auth,async(req,res)=>{const projects=await db("select p.*,coalesce(sum(case when c.fixed=true then r.completed else 0 end),0) completed from projects p left join reports r on r.project_id=p.id left join catalog c on c.id=r.task_id group by p.id order by p.id");res.json(projects)});
app.get("/api/audit",auth,admin,async(req,res)=>res.json(await db("select a.*,u.full_name,u.username,u.role,u.is_root from audit_logs a left join users u on u.id=a.actor_id order by a.id desc limit 500")));

function docText(text,opts={}){return new Paragraph({children:[new TextRun({text:String(text??""),font:"Times New Roman",size:opts.size||24,bold:Boolean(opts.bold),italics:Boolean(opts.italics)})],alignment:opts.align,spacing:{after:opts.after??100}})}
function docCell(text,bold=false){return new TableCell({children:[new Paragraph({children:[new TextRun({text:String(text??""),font:"Times New Roman",size:18,bold})]})],verticalAlign:"center"})}
function docTable(headers,rows){return new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[new TableRow({children:headers.map(x=>docCell(x,true))}),...rows.map(r=>new TableRow({children:r.map(x=>docCell(x))}))]})}
async function buildWord(project,person,rows){
 const {Document,Packer,Paragraph,TextRun,Table,TableRow,TableCell,WidthType,AlignmentType}=require("docx");
 const byTask={};for(const r of rows){const k=r.task_name;byTask[k]??={qty:0,completed:0,unit:r.unit,rows:0,notes:[]};byTask[k].qty+=Number(r.qty||0);byTask[k].completed+=Number(r.completed||0);byTask[k].rows++;if(r.note)byTask[k].notes.push(r.note)}
 const mk=(text,opts={})=>new Paragraph({children:[new TextRun({text:String(text??""),font:"Times New Roman",size:opts.size||24,bold:!!opts.bold,italics:!!opts.italics})],alignment:opts.align,spacing:{after:opts.after??100}});
 const cell=t=>new TableCell({children:[mk(String(t??""),{size:18})],verticalAlign:"center"});
 const table=(heads,data)=>new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[new TableRow({children:heads.map(t=>new TableCell({children:[mk(t,{size:18,bold:true})]}))}),...data.map(row=>new TableRow({children:row.map(cell)}))]});
 const totalQty=rows.reduce((a,r)=>a+Number(r.qty||0),0),totalDone=rows.reduce((a,r)=>a+Number(r.completed||0),0);
 const content=[
 mk("CHI NHÁNH TRUNG TÂM PHÁT TRIỂN QUỸ ĐẤT KHU VỰC BÌNH DƯƠNG",{bold:true,align:AlignmentType.CENTER}),
 mk("PHÒNG KỸ THUẬT VÀ THÔNG TIN ĐẤT ĐAI",{bold:true,align:AlignmentType.CENTER}),
 mk("CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM",{bold:true,align:AlignmentType.CENTER}),
 mk("Độc lập - Tự do - Hạnh phúc",{bold:true,align:AlignmentType.CENTER}),
 mk("Thành phố Hồ Chí Minh, ngày ..... tháng ..... năm 2026",{italics:true,align:AlignmentType.RIGHT,after:300}),
 mk("BÁO CÁO ĐỊNH KỲ",{bold:true,align:AlignmentType.CENTER}),
 mk("Về việc thực hiện Dự án:",{align:AlignmentType.CENTER}),
 mk(project.name,{bold:true,align:AlignmentType.CENTER,after:250}),
 mk("Người thực hiện: "+person,{bold:true}),
 mk("I. THÔNG TIN CÔNG TRÌNH/DỰ ÁN",{bold:true}),
 mk(" - Tên công trình/dự án: "+project.name),
 mk(" - Mã công trình: "+project.code),
 mk(" - Địa bàn: "+(project.location||"")),
 mk(" - Tổng số hộ dân bị ảnh hưởng:"),
 mk(" + Chiều dài tuyến:"),
 mk(" + Tổng số hộ dân/thửa đất bị ảnh hưởng bởi công trình:"),
 mk("II. KẾT QUẢ THỰC HIỆN",{bold:true}),
 mk("Tổng hợp báo cáo công việc của "+person+": "+rows.length+" dòng báo cáo; tổng khối lượng "+totalQty+"; đã hoàn thành "+totalDone+"."),
 mk("1. Kết quả đo đạc hiện trạng",{bold:true}),
 table(["STT","Nội dung công việc","Khối lượng báo cáo","Đã hoàn thành","Đơn vị","Ghi chú"],Object.entries(byTask).map(([name,v],i)=>[i+1,name,v.qty,v.completed,v.unit,v.notes.join("; ")])),
 mk("2. Kết quả lập bản mô tả hiện trạng ranh giới, mốc giới thửa đất",{bold:true}),
 mk("Số chủ sử dụng đất đã ký/chưa ký và số liên ranh đã ký/chưa ký:"),
 mk(""),
 mk("3. Kết quả lập phiếu đo đạc chỉnh lý thửa đất",{bold:true}),
 mk("Số lượng cụ thể theo từng trường hợp được thể hiện trong file Excel đính kèm nếu có dữ liệu."),
 mk("(Đính kèm theo danh sách Excel từng trường hợp cụ thể)",{italics:true}),
 mk("III. KHÓ KHĂN, VƯỚNG MẮC VÀ ĐỀ XUẤT KIẾN NGHỊ",{bold:true}),
 mk("1. Khó khăn, vướng mắc"),
 mk(rows.map(r=>r.note).filter(Boolean).join("; ")),
 mk("2. Đề xuất, kiến nghị"),
 mk(rows.map(r=>r.direction).filter(Boolean).join("; "))
 ];
 const doc=new Document({sections:[{properties:{page:{size:{width:11906,height:16838},margin:{top:900,bottom:900,left:1000,right:1000}}},children:content}]});
 return Packer.toBuffer(doc);
}
async function buildExcel(project,person,rows){
 const wb=new ExcelJS.Workbook();wb.creator="Báo cáo công việc";wb.created=new Date();
 const ws=wb.addWorksheet("Danh sách hồ sơ");
 ws.mergeCells("A1:T1");ws.getCell("A1").value="DANH SÁCH\nTổ chức, hộ gia đình, cá nhân có đất ảnh hưởng Dự án: "+project.name;ws.getCell("A1").alignment={wrapText:true,vertical:"middle",horizontal:"center"};ws.getCell("A1").font={bold:true,size:12};
 const headers=["STT","Tổ thực hiện","Số hộ","Số thửa","Chủ sử dụng đất","Số thửa","Số tờ BĐ","Diện tích tổng (m2)","Loại đất","Vướng mắc","Kế hoạch thực hiện, giải quyết vướng mắc","Ký bản mô tả","Ký PXN","Chuyển kiểm tra cấp đơn vị thi công","Trình lãnh đạo phòng","Trình phó giám đốc","Chuyển UBND phường kiểm tra","Đi ký dân","Bàn giao Phòng BT&GPMB","Bàn giao Phòng BT ranh GPMB"];
 ws.addRow(headers);const hr=ws.getRow(2);hr.font={bold:true};hr.alignment={wrapText:true,vertical:"middle",horizontal:"center"};hr.height=58;
 // Không tự suy đoán thông tin từng hộ/thửa khi hệ thống chưa lưu các trường này.
 const notes=[...new Set(rows.map(r=>r.note).filter(Boolean))].join("; ");
 ws.addRow([1,person,"","","","","","","",notes,[...new Set(rows.map(r=>r.direction).filter(Boolean))].join("; "),"","","","","","","","",""]);
 const widths=[7,20,10,10,26,12,12,17,12,30,36,14,12,20,17,17,22,14,23,25];widths.forEach((w,i)=>ws.getColumn(i+1).width=w);
 ws.eachRow(row=>row.eachCell(cell=>{cell.alignment={...(cell.alignment||{}),vertical:"top",wrapText:true};cell.border={top:{style:"thin",color:{argb:"FFD9E2F0"}},left:{style:"thin",color:{argb:"FFD9E2F0"}},bottom:{style:"thin",color:{argb:"FFD9E2F0"}},right:{style:"thin",color:{argb:"FFD9E2F0"}}}}));
 const detail=wb.addWorksheet("Chi tiết báo cáo");detail.addRow(["Ngày","Giờ","Người thực hiện","Mã công trình","Công trình","Nội dung công việc","Khối lượng","Đã hoàn thành","Đơn vị","Ghi chú","Nhận xét","Chỉ đạo","Trạng thái"]);
 for(const r of rows)detail.addRow([r.report_date?new Date(r.report_date).toLocaleDateString("vi-VN"):"",r.report_time?String(r.report_time).slice(0,5):"",person,project.code,project.name,r.task_name,r.qty,r.completed,r.unit,r.note||"",r.review||"",r.direction||"",r.status||""]);
 detail.columns=[{width:13},{width:10},{width:24},{width:15},{width:28},{width:34},{width:14},{width:14},{width:13},{width:32},{width:32},{width:32},{width:16}];detail.views=[{state:"frozen",ySplit:1}];
 [ws,detail].forEach(sh=>{sh.autoFilter={from:{row:2,column:1},to:{row:sh.rowCount,column:sh.columnCount}};sh.getRow(1).font={bold:true,size:12};});
 return wb.xlsx.writeBuffer();
}
app.get("/api/exports/reports.zip",auth,admin,async(req,res)=>{
 try{
  const rows=await db("select r.*,p.code project_code,p.name project_name,p.location project_location,u.full_name person from reports r join projects p on p.id=r.project_id join users u on u.id=r.user_id order by p.name,u.full_name,r.report_date,r.report_time,r.id");
  if(!rows.length)return res.status(404).json({error:"Chưa có báo cáo để xuất"});
  const groups=new Map();for(const r of rows){const key=r.project_id+"_"+r.user_id;if(!groups.has(key))groups.set(key,{project:{id:r.project_id,code:r.project_code,name:r.project_name,location:r.project_location},person:r.person,rows:[]});groups.get(key).rows.push(r)}
  res.setHeader("Content-Type","application/zip");res.setHeader("Content-Disposition",'attachment; filename="Bao_cao_cong_trinh_Word_Excel.zip"');
  const zip=archiver("zip",{zlib:{level:6}});zip.on("error",e=>{if(!res.headersSent)res.status(500);res.end()});zip.pipe(res);
  for(const g of groups.values()){
   const safe=s=>String(s||"").normalize("NFD").replace(/[\u0300-\u036f]/g,"").replace(/đ/g,"d").replace(/Đ/g,"D").replace(/[^a-zA-Z0-9_-]+/g,"_").replace(/^_+|_+$/g,"").slice(0,70)||"Bao_cao";
   const base=safe(g.project.code+"_"+g.project.name+"_"+g.person);
   const doc=await buildWord(g.project,g.person,g.rows);zip.append(doc,{name:base+"/"+base+".docx"});
   const xlsx=await buildExcel(g.project,g.person,g.rows);zip.append(Buffer.from(xlsx),{name:base+"/"+base+".xlsx"});
  }
  await zip.finalize();
 }catch(e){console.error("export reports",e);if(!res.headersSent)res.status(500).json({error:"Không tạo được bộ báo cáo: "+e.message})}
});

app.get("/{*splat}",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

init().then(()=>app.listen(process.env.PORT||3000,()=>console.log("BaoCaoCongViec V2.0 running"))).catch(e=>{console.error(e);process.exit(1)});
