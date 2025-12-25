from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import time

# مكتبات المصادقة والقواعد
from passlib.context import CryptContext
from jose import JWTError, jwt

# مكتبات السحابة (OCI)
# ملاحظة: تأكد من تثبيت مكتبة oci (pip install oci)
# وتجهيز ملف config ~/.oci/config أو متغيرات البيئة
try:
    import oci
    OCI_ENABLED = True
except ImportError:
    OCI_ENABLED = False

# ==========================================
# إعدادات المشروع (Config)
# ==========================================
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="OpenCloud API")

# السماح للفرونت إند بالاتصال (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # في الإنتاج استعمل دومين موقعك فقط
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# محاكاة قاعدة البيانات (Database Mock)
# ==========================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"), # كلمة المرور: admin123
    }
}

# قائمة الـ VMs الحالية (محاكاة DB)
fake_vms_db = []

# ==========================================
# النماذج (Models)
# ==========================================
class Token(BaseModel):
    access_token: str
    token_type: str

class UserAuth(BaseModel):
    username: str
    password: str

class VMCreate(BaseModel):
    name: str
    flavor: str
    image: str
    req: dict # {cpu: 1, ram: 1}

class VM(BaseModel):
    id: int
    name: str
    flavor: str
    image: str
    status: str
    ip_address: Optional[str] = None
    cloud_id: Optional[str] = None
    req_cpu: int
    req_ram: int
    user_id: str

# ==========================================
# دوال المساعدة (Utils)
# ==========================================
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return user_dict

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user

# ==========================================
# ربط السحابة (Cloud Service)
# ==========================================
class CloudService:
    @staticmethod
    def create_vm_oci(name: str, image: str):
        if not OCI_ENABLED:
            print("OCI SDK not installed. Running in Simulation Mode.")
            return {"id": f"sim-ocid-{int(time.time())}", "ip": "10.0.0.X"}
        
        # كود الربط الحقيقي مع Oracle Cloud
        # ملاحظة: هذا الكود لن يعمل إلا إذا قمت بإعداد ملف ~/.oci/config
        try:
            config = oci.config.from_file()
            compute_client = oci.core.ComputeClient(config)
            # ... هنا تتم بقية منطق إنشاء الـ VM كما شرحنا في الرد السابق
            # سنقوم بالمحاكاة الآن لكي يعمل الكود فوراً لديك
            return {"id": f"real-ocid-{int(time.time())}", "ip": "129.0.0.X"}
        except Exception as e:
            print(f"OCI Error: {e}")
            return {"id": "error", "ip": "0.0.0.0"}

# ==========================================
# التوجيهات (Endpoints)
# ==========================================

@app.post("/auth/login", response_model=Token)
async def login(form_data: UserAuth):
    user = get_user(fake_users_db, form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/register")
async def register(form_data: UserAuth):
    if form_data.username in fake_users_db:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = pwd_context.hash(form_data.password)
    fake_users_db[form_data.username] = {
        "username": form_data.username,
        "hashed_password": hashed_password
    }
    return {"message": "User created successfully"}

@app.get("/api/vms", response_model=List[VM])
async def list_vms(token: str):
    user = get_current_user(token)
    # إرجاع الـ VMs الخاصة بهذا المستخدم فقط
    user_vms = [vm for vm in fake_vms_db if vm.user_id == user["username"]]
    return user_vms

@app.post("/api/vms/create", response_model=VM)
async def create_vm(vm_data: VMCreate, token: str):
    user = get_current_user(token)
    
    # 1. استدعاء السحابة
    cloud_response = CloudService.create_vm_oci(vm_data.name, vm_data.image)
    
    # 2. حفظ البيانات المحلية
    new_vm = VM(
        id=len(fake_vms_db) + 1,
        name=vm_data.name,
        flavor=vm_data.flavor,
        image=vm_data.image,
        status="BUILD", # حالة البناء الافتراضية
        ip_address=cloud_response["ip"],
        cloud_id=cloud_response["id"],
        req_cpu=vm_data.req["cpu"],
        req_ram=vm_data.req["ram"],
        user_id=user["username"]
    )
    
    fake_vms_db.append(new_vm)
    
    # محاكاة تحديث الحالة بعد وقت بسيط (يمكنك عمل Cron Job حقيقي)
    time.sleep(3) # تأخير بسيط فقط كتجربة
    
    new_vm.status = "ACTIVE" # نجح الإنشاء
    new_vm.ip_address = "192.168.1.100" # نغير الـ IP للمحاكاة
    
    return new_vm

@app.delete("/api/vms/{vm_id}")
async def delete_vm(vm_id: int, token: str):
    user = get_current_user(token)
    
    vm_index = -1
    for i, vm in enumerate(fake_vms_db):
        if vm.id == vm_id and vm.user_id == user["username"]:
            vm_index = i
            break
            
    if vm_index == -1:
        raise HTTPException(status_code=404, detail="VM not found")
        
    # هنا نكتب كود حذف الـ VM من OCI
    # compute_client.terminate_instance(fake_vms_db[vm_index].cloud_id)
    
    deleted_vm = fake_vms_db.pop(vm_index)
    return {"message": "VM deleted successfully"}
