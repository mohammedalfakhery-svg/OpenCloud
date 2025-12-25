from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import boto3           # استيراد مكتبة AWS
from botocore.exceptions import ClientError

# مكتبات المصادقة والقواعد
from passlib.context import CryptContext
from jose import JWTError, jwt

# ==========================================
# إعدادات المشروع (Config)
# ==========================================
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# إعدادات AWS
AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY_HERE"    # ضع المفتاح هنا
AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_KEY_HERE" # ضع السر هنا
AWS_REGION = "us-east-1"
# AMI ID لـ Ubuntu 22.04 في منطقة us-east-1 (مجاني مع t2.micro)
# إذا كنت في منطقة أخرى، يجب تغيير هذا الـ ID من موقع AWS
DEFAULT_AMI_ID = "ami-05c13eab67c5d8861" 

app = FastAPI(title="OpenCloud AWS API")

# إعدادات CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# الاتصال بـ EC2
try:
    ec2_resource = boto3.resource(
        'ec2',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )
    print("✅ تم الاتصال بـ AWS EC2 بنجاح.")
except Exception as e:
    print(f"❌ خطأ في الاتصال بـ AWS: {e}")
    ec2_resource = None

# ==========================================
# محاكاة قاعدة البيانات
# ==========================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"),
    }
}

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
    req: dict 

class VM(BaseModel):
    id: str
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
# دوال المساعدة (Auth)
# ==========================================
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        return db[username]

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = get_user(fake_users_db, username)
    if user is None: raise HTTPException(status_code=401, detail="User not found")
    return user

# ==========================================
# خدمة السحابة AWS (EC2 Logic)
# ==========================================
class AWSCloudService:
    @staticmethod
    def create_vm_oci(vm_name: str, username: str):
        if not ec2_resource: return None

        # 1. تحديد نوع الخادم (Flavor)
        # قيد أمني: نلزم الجميع باستخدام t2.micro لتجنب الفوترة
        instance_type = "t2.micro" 
        
        try:
            # إنشاء الخادم
            instances = ec2_resource.create_instances(
                ImageId=DEFAULT_AMI_ID,
                MinCount=1,
                MaxCount=1,
                InstanceType=instance_type,
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': vm_name},
                            {'Key': 'CreatedBy', 'Value': username} # مهم لتتبع المالك
                        ]
                    },
                ],
                KeyName="my-key-pair" # يجب إنشاء KeyPair في AWS مسبقاً أو إزالة هذا السطر
            )
            
            instance = instances[0] # نأخذ المثيل الأول
            # انتظار بدء التشغيل للحصول على الـ IP
            instance.wait_until_running()
            instance.reload()

            return {
                "id": instance.id,
                "ip": instance.public_ip_address,
                "status": instance.state['Name']
            }
        except ClientError as e:
            print(f"AWS Error: {e}")
            return None

    @staticmethod
    def list_vms(username: str):
        if not ec2_resource: return []
        
        # جلب الخوادم المفعلة فقط
        try:
            # الطريقة الأفضل: جلب كل الخوادم التي تحمل تاج باسم المستخدم
            # ملاحظة: الفلترة بالتاج قد تستغرق وقتاً طويلاً إذا كان عندك آلاف الخوادم
            # للتعليم، سنقوم بجلب الخوادم كلها وتفلترتها برمجياً
            instances = ec2_resource.instances.filter(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'pending', 'stopping', 'stopped']}]
            )
            
            vm_list = []
            for i in instances:
                # استخراج اسم الخادم من الـ Tags
                name = "Unknown"
                owner = "Unknown"
                for tag in i.tags or []:
                    if tag['Key'] == 'Name': name = tag['Value']
                    if tag['Key'] == 'CreatedBy': owner = tag['Value']
                
                # إظهار فقط خوادم هذا المستخدم
                if owner == username:
                    status_map = {'running': 'ACTIVE', 'pending': 'BUILD', 'stopped': 'STOPPED'}
                    
                    vm_list.append({
                        "id": i.id,
                        "name": name,
                        "status": status_map.get(i.state['Name'], i.state['Name']),
                        "flavor": i.instance_type, # مثل t2.micro
                        "image": i.image_id,
                        "ip": i.public_ip_address or "N/A"
                    })
            return vm_list
        except Exception as e:
            print(f"List Error: {e}")
            return []

    @staticmethod
    def delete_vm(instance_id: str):
        if not ec2_resource: return False
        try:
            instance = ec2_resource.Instance(instance_id)
            # التأكد من أن الخادم مملوك للمشروع (اختياري)
            instance.terminate()
            return True
        except Exception as e:
            print(f"Delete Error: {e}")
            return False

# ==========================================
# API Endpoints
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
    fake_users_db[form_data.username] = {"username": form_data.username, "hashed_password": pwd_context.hash(form_data.password)}
    return {"message": "User created successfully"}

@app.get("/api/vms", response_model=List[VM])
async def list_vms(token: str):
    user = get_current_user(token)
    
    # جلب الخوادم الفعلية من AWS بناءً على اسم المستخدم
    real_vms = AWSCloudService.list_vms(user["username"])
    
    # تحويلها للنموذج الخاص بنا
    response_vms = []
    for vm in real_vms:
        response_vms.append(VM(
            id=vm["id"],
            name=vm["name"],
            flavor=vm["flavor"],
            image=vm["image"],
            status=vm["status"],
            ip_address=vm["ip"],
            cloud_id=vm["id"],
            req_cpu=1, # t2.micro يساوي 1 vCPU بشكل افتراضي
            req_ram=1,
            user_id=user["username"]
        ))
    return response_vms

@app.post("/api/vms/create", response_model=VM)
async def create_vm(vm_data: VMCreate, token: str):
    user = get_current_user(token)
    
    # --- قيد الحماية ---
    # التأكد أن المستخدم لا يملك أكثر من خادم واحد حالياً لتجنب التكلفة
    existing_vms = AWSCloudService.list_vms(user["username"])
    if len(existing_vms) >= 1:
        raise HTTPException(status_code=403, detail="حماية: لا يمكن إنشاء أكثر من خادم واحد لكل مستخدم لضمان الحفاظ على الرصيد المجاني.")
    # --------------------
    
    # استدعاء AWS
    result = AWSCloudService.create_vm_oci(vm_data.name, user["username"])
    
    if not result:
        raise HTTPException(status_code=500, detail="فشل الاتصال بـ AWS أو تم رفض الطلب.")
        
    new_vm = VM(
        id=result["id"],
        name=vm_data.name,
        flavor="t2.micro", # سنفرض النوع دائماً
        image="Ubuntu 22.04 (AWS)",
        status="BUILD", # لأنه سيعمل قليلاً قبل أن يصبح Running
        ip_address=result["ip"],
        cloud_id=result["id"],
        req_cpu=1,
        req_ram=1,
        user_id=user["username"]
    )
    
    return new_vm

@app.delete("/api/vms/{vm_id}")
async def delete_vm(vm_id: str, token: str):
    user = get_current_user(token)
    
    success = AWSCloudService.delete_vm(vm_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="VM not found or could not be deleted")
        
    return {"message": "VM terminated successfully"}
