from fastapi import FastAPI, Request, Form, HTTPException,UploadFile,File, status
from fastapi.staticfiles import StaticFiles
from supabase import create_client, Client
import hashlib, json
import httpx
from firebase_admin import auth, db, credentials
import firebase_admin
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse,RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime
import os   
import random,string
import requests
from dotenv import load_dotenv

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")

app = FastAPI()
load_dotenv() 

app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    SessionMiddleware,
    secret_key = os.getenv("secret"),
    https_only = False,
    max_age = 60*60*24
)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

firebase_json_raw = os.getenv("file")
if firebase_json_raw:
    try:
        cert_dict = json.loads(firebase_json_raw)
        
        if "private_key" in cert_dict:
            cert_dict["private_key"] = cert_dict["private_key"].replace("\\n", "\n")
            
        if not firebase_admin._apps:
            cred = credentials.Certificate(cert_dict)
            firebase_admin.initialize_app(cred, {"databaseURL": os.getenv("url")})
    except Exception as e:
        print(f"Firebase Init Error: {e}")
templates = Jinja2Templates(directory="Templates")
@app.get("/",response_class=HTMLResponse)
def home(request : Request):
    return templates.TemplateResponse("home.html",{"request": request})



@app.get("/login", response_class=HTMLResponse)
def log_screen(request : Request):
    return templates.TemplateResponse("login.html",{"request": request})

@app.get("/register", response_class=HTMLResponse)
def reg_screen(request : Request):
    return templates.TemplateResponse("register.html",{"request": request})


@app.post("/register", response_class=RedirectResponse)
async def reg_user(
    request = Request,
    email : str= Form(...),
    password : str = Form(...),
    fullname : str = (Form(...)),
    orgname : str = (Form(...)),
    role : str = Form(...),
    regCode : str = (Form   (...))
):
    
    user = auth.create_user(
        email = email,
        password = password
    )

    uid = user.uid

    ref = db.reference(f"users/{uid}")
    ref.set({
        "email" : email,
        "fullname" : fullname.title(),
        "OrgName" : orgname.upper(),
        "Role" : role,
        "ID" : regCode.upper(),
        "Status" : "approved",
        "tamper": 0,
        "isBlacklisted": False
    })

    msg = f'''User registered 
    email : {email},
    fullname : {fullname},
    orgname: {orgname},
    role: {role},
    ID : {regCode},
    Your status is currently pending we will let you know when the admi n has approved your request'''

    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

async def chk_user(email: str, password: str):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"

    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.post(url, json=payload)
            data = response.json()

            if response.status_code == 200:
                return data, None
            else:
                return None, data

        except httpx.ConnectTimeout:
            return None, {"error": {"message": "CONNECTION_TIMEOUT"}}

        except httpx.ReadTimeout:
            return None, {"error": {"message": "READ_TIMEOUT"}}

        except Exception as e:
            return None, {"error": {"message": f"UNKNOWN_ERROR: {str(e)}"}}



@app.post("/login", response_class=RedirectResponse)
async def login_usr(
    request : Request,
    email : str = Form(...),
    password : str = Form(...),
    role : str = Form(...)
    ):

    data, error = await chk_user(email, password)
    if error:
        raise HTTPException(400, error["error"]["message"])
    
    uid = data.get("localId")

    if not uid:
        raise HTTPException(400, "No uid was found in the database")
    

    ref = db.reference(f"/users/{uid}")
    user_data = ref.get()

    if not user_data:
        raise HTTPException(400, "User profile not found")

    status = user_data.get("Status") 
    role_actual = user_data.get("Role")

    if status != "approved":
        
        return templates.TemplateResponse("pending.html",{
            "request" : request,
            "message": "Login successful, but your account is not approved yet",
            "status": status,
            "user": user_data
        })

    elif role == role_actual:
        if role == "manufacturer":
            request.session["uid"] = uid 
            return RedirectResponse(url = "manufacturer/dashboard", status_code=303)
        
        elif role == "distributor":
            request.session["uid"] = uid 
            return RedirectResponse(url = "distributor/dashboard", status_code=303)
        
        elif role == "pharmacy":
            request.session["uid"] = uid 
            return RedirectResponse(url = "pharmacy/dashboard", status_code=303)
    else:
        return templates.TemplateResponse(
            "error.html",
            {
                "request" : request,
                "hypo" : role,
                "actual" : role_actual
            }
        )
   
async def info_finder(uid : str):
    ref = db.reference(f"users/{uid}")
    user_data = ref.get()
    if not user_data:
        raise HTTPException(400, "User profile not found")
    
    return user_data
async def org_finder(id : str):
    ref = db.reference("/users/")
    persons = ref.get()
    for uid, data in persons.items():
        if data.get("ID") == id:
            return data.get("OrgName")

async def genesis_data_finder(batchID : str):
    ref = db.reference(f"blocks/{batchID}/0")
    user_data = ref.get()
    if not user_data:
        raise HTTPException(400, "Block not found")
    
    return user_data


@app.get("/distributor/dashboard", response_class=HTMLResponse)
async def dis_dash(request : Request):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    data = await info_finder(uid)
    return templates.TemplateResponse("distributor-dash.html", {
        "request" : request,
        "fname" : data.get("fullname"),
        "email" : data.get("email"),
        "orgname" : data.get("OrgName"),
        "role" : data.get("Role").upper(),
        "regCode" : data.get("ID"),
        "stat" : data.get("tamper"),
        "title" : f"{data.get("Role").upper()}'s Dashboard"


        })
def get_secondary(blocks):
    if isinstance(blocks, list):
        return blocks if len(blocks) == 2  else None
    if isinstance(blocks, dict):
        return (blocks or blocks) if len(blocks) == 2 else None
    return None
async def generateBatch(disID : str):
    block_ref = db.reference("/blocks/")
    all_batches = block_ref.get()

    if not all_batches:
        return []
    
    matched_batches = []

    for batchID, batch_data in all_batches.items():
        block = get_secondary(batch_data)

        if block and block[1].get("data").get("disID") == disID:
            matched_batches.append({
                "batchID" : batchID,
                **block[0]
            })
    return matched_batches

@app.get("/distributor/incoming", response_class=HTMLResponse)
async def incoming_batch(request : Request):
    uid = request.session.get("uid")

    if not uid:
        return RedirectResponse("/login")
    
    user_data = await info_finder(uid)
    if not user_data:
        raise HTTPException(400, "User not found")
    disID =user_data.get("ID")
    batches = await generateBatch(disID)

    return templates.TemplateResponse("distributor-get.html", {
        "request" : request,
        "batches" : batches,
        "title": f"Incoming Shipments of {user_data.get("OrgName").title()}",
        "orgname": user_data.get("OrgName")
    })

@app.post("/distributor/forward", response_class=RedirectResponse)
async def genthirdblock(
    request : Request, 
    batchID : str = Form(...),
    phmID : str = Form(...),
    dvrname : str = Form(...),
    confirm : str = Form(...),
    vnum : str = Form(...),
    shipdate : str = Form(...),
    estdeldate : str = Form(...),
    condition : UploadFile = Form(...)
    ):
    if "uid" not in request.session:
        return RedirectResponse("/login")
    ref = db.reference(f"/blocks/{batchID}/1")
    gen_block = ref.get()
    prevHash = gen_block.get("hash")
    disID = gen_block.get("data").get("disID")
    if condition:
        safe_filename = condition.filename.replace(" ", "_").replace("'", "")
        file_ext = safe_filename.split('.')[-1].lower()

        if file_ext == "pdf":
            content_type = "application/pdf"
        elif file_ext in ["jpg", "jpeg"]:
            content_type = "image/jpeg"
        elif file_ext == "png":
            content_type = "image/png"
        else:
            content_type = "application/octet-stream"

        cert_path = f"batches/{batchID}/distributor/conditionofbatch_{batchID}_{safe_filename}"
        cert_bytes = await condition.read()
        supabase.storage.from_("cert_upload").upload(cert_path, cert_bytes, file_options={"content-type":content_type})
        condition_url = supabase.storage.from_("cert_upload").get_public_url(cert_path)
        hashedcondition = hashlib.sha256(cert_bytes).hexdigest()

        block = {
            "prev_hash" : prevHash,
            "timestamp" : datetime.now().strftime("%d-%m-%Y %H:%M:%S.%f"),
            "data" : {
                "phmID" : phmID.upper(),
                "disID" : disID,
                "PhmOrgName" : await org_finder(phmID.upper()),
                "dvrname" : dvrname,
                "vnum" : vnum,
                "notDamaged" : confirm,
                "shipdate" : shipdate,
                "estdate" : estdeldate,
                "files" : {
                    "Conditionurl" : condition_url,
                    "conditionhash" : hashedcondition
                }

            }
        }
        encoded_block = json.dumps(block, sort_keys=True).encode()
        encoded_block_hash = hashlib.sha256(encoded_block).hexdigest()
        block["hash"] = encoded_block_hash
        ref = db.reference(f"/blocks/{batchID}/2")
        ref.set(block)
        return RedirectResponse(url="/distributor/history", status_code=status.HTTP_303_SEE_OTHER)

    

@app.get("/distributor/forward/{batchID}", response_class=HTMLResponse)
async def third_block(request : Request, batchID : str):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    

    
    return templates.TemplateResponse("distributor-forward.html",{
        "request" : request,
        "title" : f"Outgoing Batch ({batchID})",
        "batchID" : batchID,
        
    })

@app.post("/manufacturer/forward",response_class=RedirectResponse)
async def gen_secblock(
    request: Request,
    batchID : str = Form(...),
    disID : str = Form(...),
    dvrname : str = Form(...),
    vnum : str = Form(...),
    shipdate : str = Form(...),
    deldate : str = Form(...)  
):
    if "uid" not in request.session:
        return RedirectResponse("/login")
    ref = db.reference(f"/blocks/{batchID}/0")
    gen_block = ref.get()
    prevHash = gen_block.get("hash")

    mfgID = gen_block.get("data").get("mfgID")
    data = {
        "disID" : disID.upper(),
        "dvrname" : dvrname,
        "vnum" : vnum,
        "mfgID" :mfgID,
        "shipdate" : shipdate,
        "deldate" : deldate,
        "DisOrgName" : await org_finder(disID.upper())
    }
    block_data = {
        "data" : data,
        "timestamp" : datetime.now().strftime("%d-%m-%Y %H:%M:%S.%f"),
        "prev_hash" : prevHash

    }
    ref = db.reference(f"/blocks/{batchID}/1")

    encoded_block = json.dumps(block_data, sort_keys=True).encode()
    hash = hashlib.sha256(encoded_block).hexdigest()
    block_data["hash"] = hash
    ref.set(block_data)
    return RedirectResponse (url="/manufacturer/history", status_code=status.HTTP_303_SEE_OTHER)



    

@app.get("/manufacturer/forward/{batchID}", response_class=HTMLResponse)
async def second_block(request : Request, batchID : str):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    
    return templates.TemplateResponse("manufacturer-forward.html",{
        "request" : request,
        "title" : f"Outgoing Batch ({batchID})",
        "batchID" : batchID,
        
    })
@app.get("/manufacturer/dashboard", response_class=HTMLResponse)
async def dis_dash(request : Request):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    data = await info_finder(uid)
    return templates.TemplateResponse("manufacturer-dash.html", {
        "request" : request,
        "fname" : data.get("fullname"),
        "email" : data.get("email"),
        "orgname" : data.get("OrgName"),
        "role" : data.get("Role").upper(),
        "regCode" : data.get("ID"),
        "stat" : data.get("tamper"),
        "title" : f"{data.get("Role").title()}'s Dashboard"
        })

@app.get("/manufacturer/create-batch", response_class=HTMLResponse)
async def gen_block(request : Request):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    
    data = await info_finder(uid)
    return templates.TemplateResponse("manufacturer-create.html", {"request" : request, "mfgID" : data.get("ID"),"orgnm" : data.get("OrgName"),"title" : "Create a batch"})


def make_batchID(mfgid):
    datenow = datetime.now()
    random_char = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

    batchID = f"{mfgid.upper()[:6]}-{datenow.strftime("%Y%m%d")}-{random_char}"
    return batchID


@app.post("/manufacturer/create-batch", response_class=RedirectResponse)
async def create_batch(
    request: Request,
    mfgID : str = Form(...),
    orgnm: str = Form(...),
    medname: str = Form(...),
    qty: int = Form(...),
    mfgdate: str = Form(...),
    expdate: str = Form(...),
    description: str = Form(None),
    certificate: UploadFile = File(...),
    labReport: UploadFile = File(None)
):
    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse("/login")
    
    ref = db.reference(f"users/{uid}")
    user_data = ref.get()
    if not user_data:
        raise HTTPException(400, "User profile not found")
    
    batchID = make_batchID(mfgID)
    time_now = datetime.now()
    
    data = {
        "mfgID": mfgID,
        "MfgOrgName": orgnm,
        "medname": medname,
        "quantity": qty,
        "mfgdate": mfgdate,
        "expdate": expdate,
        "description": description or ""
    }
    block_data = {
        "data" : data,
        "timestamp": time_now.strftime("%d-%m-%Y %H:%M:%S.%f"),
        "prev_hash": "00000000"
    }

    
    
    certificate_url = None
    labreport_url = None
    
    if certificate:
        safe_filename = certificate.filename.replace(" ", "_").replace("'", "")
        file_ext = safe_filename.split('.')[-1].lower()

        if file_ext == "pdf":
            content_type = "application/pdf"
        elif file_ext in ["jpg", "jpeg"]:
            content_type = "image/jpeg"
        elif file_ext == "png":
            content_type = "image/png"
        else:
            content_type = "application/octet-stream"

        safe_filename = certificate.filename.replace(" ", "_").replace("'", "")
        cert_path = f"batches/{batchID}/manufacturer/certificate_{safe_filename}"
        cert_bytes = await certificate.read()
        supabase.storage.from_("cert_upload").upload(cert_path, cert_bytes, file_options={"content-type":content_type})
        certificate_url = supabase.storage.from_("cert_upload").get_public_url(cert_path)
        hashedcertificate = hashlib.sha256(cert_bytes).hexdigest()
    
    if labReport and labReport.filename:
        safe_filename = labReport.filename.replace(" ", "_").replace("'", "")
        lab_bytes = await labReport.read()
        if lab_bytes:
            file_ext = safe_filename.split('.')[-1].lower()

            if file_ext == "pdf":
                content_type = "application/pdf"
            elif file_ext in ["jpg", "jpeg"]:
                content_type = "image/jpeg"
            elif file_ext == "png":
                content_type = "image/png"
            else:
                content_type = "application/octet-stream"

            
            lab_path = f"batches/{batchID}/manufacturer/labreport_{safe_filename}"
            supabase.storage.from_("cert_upload").upload(lab_path, lab_bytes, file_options={"content-type":content_type})
            labreport_url = supabase.storage.from_("cert_upload").get_public_url(lab_path)
            hashedlabreports = hashlib.sha256(lab_bytes).hexdigest()

            block_data["data"]["files"] = {
                "certificate": certificate_url,
                "certHash" : hashedcertificate,
                "labReport": labreport_url,
                "labHash" : hashedlabreports
            }

    else:
            block_data["data"]["files"] = {
                "certificate": certificate_url,
                "certHash" : hashedcertificate,
                "labReport": "",
                "labHash" : ""
            }

    
    block_string = json.dumps(block_data, sort_keys=True).encode()
    block_hash = hashlib.sha256(block_string).hexdigest()
    block_data["hash"] = block_hash
    
    
    
    batch_ref = db.reference(f"blocks/{batchID}/0")
    batch_ref.set(block_data)
    
    return RedirectResponse(url = "/manufacturer/outgoing", status_code=303)
def onlyfreshmfg(blocks):
    if isinstance(blocks, list):
        return blocks[0] if len(blocks) == 1 else None
    if isinstance(blocks, dict):
        return (blocks.get("0") or blocks.get(0)) if len(blocks) == 1 else None
    return None
async def unsentbatch(mfgID):
    block_ref = db.reference("/blocks/")
    all_batches = block_ref.get()

    if not all_batches:
        return []
    matched_ones = []
    for batchID , batchdata in all_batches.items():
        required_batch = onlyfreshmfg(batchdata)
        if required_batch and required_batch.get("data").get("mfgID") == mfgID:
            matched_ones.append({

                "batchID" : batchID,
                **required_batch
            }
            )
    return matched_ones
    
    

@app.get("/manufacturer/outgoing", response_class=HTMLResponse)
async def block_unsent(request:Request):    
    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse("/login")
    
    user_data = await info_finder(uid)
    if not user_data:
        raise HTTPException(400, "User not found")
    mfgID =user_data.get("ID")
    batches = await unsentbatch(mfgID)
    return templates.TemplateResponse("manufacturer-get.html", {
        "request" : request,
        "batches" : batches,
        "title": f"Outgoing Shipments of {user_data.get("OrgName").title()}",
        "orgname": user_data.get("OrgName")
    })
def batchinfo(blocks):
    if isinstance(blocks, list):
        return blocks[0] if len(blocks) >0 else None
    if isinstance(blocks, dict):
        return (blocks.get("0") or blocks.get(0)) if len(blocks) > 0 else None
async def batchstatus(mfgID):
    block_ref = db.reference("/blocks/")
    all_batches = block_ref.get()

    if not all_batches:
        return []
    matched_ones = []
    for batchID , batchdata in all_batches.items():
        required_batch = batchinfo(batchdata)
        if required_batch and required_batch.get("data").get("mfgID") == mfgID:
            required_batch["length"] = len(batchdata)
            matched_ones.append({

                "batchID" : batchID,
                **required_batch
            })
            print(required_batch)
    return matched_ones
    
@app.get("/manufacturer/history", response_class=HTMLResponse)
async def batch_history(request : Request):
    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse("/login")
    
    user_data = await info_finder(uid)
    if not user_data:
        raise HTTPException(400, "User not found")
    mfgID =user_data.get("ID")

    batches = await batchstatus(mfgID)
    return templates.TemplateResponse("manufacturer-history.html",{
        "request" : request,
        "batches" : batches,
        "title": f"Shipments of {user_data.get("OrgName").title()}"
    })
    
@app.get("/pharmacy/history", response_class=HTMLResponse)
async def batch_history(request : Request):
    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse("/login")
    
    user_data = await info_finder(uid)
    if not user_data:
        raise HTTPException(400, "User not found")
    phmID =user_data.get("ID")

    batches = await batchposn(phmID, "phmID")
    return templates.TemplateResponse("pharmacy-history.html",{
        "request" : request,
        "batches" : batches,
        "title": f"Shipments of {user_data.get("OrgName").title()}"
    })

@app.get("/pharmacy/dashboard", response_class=HTMLResponse)
async def dis_dash(request : Request):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    data = await info_finder(uid)
    return templates.TemplateResponse("pharmacy-dash.html", {
        "request" : request,
        "fname" : data.get("fullname"),
        "email" : data.get("email"),
        "orgname" : data.get("OrgName"),
        "role" : data.get("Role").upper(),
        "regCode" : data.get("ID"),
        "stat" : data.get("tamper"),
        "title" : f"{data.get("Role").title()}'s Dashboard"


        })
ROLE_INDEX = {
    "mfgID": 0,
    "disID": 1,
    "phmID": 2
}
async def batchposn(ID, role):
    block_ref = db.reference("/blocks/")
    all_batches = block_ref.get()

    if not all_batches:
        return []

    matched_ones = []
    idx = ROLE_INDEX.get(role)

    for batchID, batchdata in all_batches.items():

        
        if not isinstance(batchdata, list):
            continue

        if idx >= len(batchdata):
            continue

        block = batchdata[idx]
        data = block.get("data", {})

        if data.get(role) == ID:
            matched_ones.append({
                "batchID": batchID,
                "initialdata": batchdata,
                "length": len(batchdata)
            })

    return matched_ones
@app.get("/pharmacy/incoming", response_class=HTMLResponse)
async def batch_incoming(request : Request):
    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse("/login")
    
    user_data = await info_finder(uid)
    if not user_data:
        raise HTTPException(400, "User not found")
    phmID =user_data.get("ID")

    batches = await batchposn(phmID,"phmID")
    return templates.TemplateResponse("pharmacy-get.html",{
        "request" : request,
        "batches" : batches,
        "title": f"Shipments of {user_data.get("OrgName").title()}"
    })
@app.get("/distributor/history", response_class=HTMLResponse)
async def batch_incoming(request : Request):
    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse("/login")
    
    user_data = await info_finder(uid)
    if not user_data:
        raise HTTPException(400, "User not found")
    disID =user_data.get("ID")

    batches = await batchposn(disID, "disID")
    return templates.TemplateResponse("distributor-history.html",{
        "request" : request,
        "batches" : batches,
        "title": f"Incoming Shipments of {user_data.get("OrgName").title()}"
    })

@app.get("/pharmacy/verify/{batchID}", response_class=HTMLResponse)
async def third_block(request : Request, batchID : str):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    
    ref = db.reference(f"/blocks/{batchID}/0")
    qty = ref.get().get("data").get("quantity")

    
    return templates.TemplateResponse("pharmacy-verify.html",{
        "request" : request,
        "title" : f"Verify Batch ({batchID})",
        "batchID" : batchID

        
    })
@app.post("/pharmacy/verify", response_class=RedirectResponse)
async def final(
    request : Request,
    batchID : str = Form(...),
    condition : str = Form(...),
    deldate : str = Form(...),
    totalQty : str = Form(None),
    safeQty : str = Form(None),
    damagedQty : str = Form(None),
    description : str = Form(None),
    evidence : UploadFile = Form(None),
    correctBatch : str = Form(None),
    matchQty : str = Form(None),
    batchExp : str = Form(None),
    confirm : str = Form(None)
    ):
    uid = request.session.get("uid")
    if "uid" not in request.session:
        return RedirectResponse("/login")
    
    if condition == "OK":
        ref = db.reference(f"/blocks/{batchID}/2")
        info = ref.get()
        phmID = info.get("data").get("phmID")
        prev_hash = info.get("hash")

        block_data = {
            "data" : {
                "batchVerified" : correctBatch,
                "qtyMatched" : matchQty,
                "checkExpiry" : batchExp,
                "responsibility" : confirm,
                "phmID" : phmID,
                "deldate" : deldate
            },
            "prev_hash" : prev_hash,
            "timestamp" : datetime.now().strftime("%d-%m-%Y %H:%M:%S.%f")
        }

        encoded_block = json.dumps(block_data, sort_keys=True).encode()
        hash = hashlib.sha256(encoded_block).hexdigest()
        block_data["hash"] = hash

        ref = db.reference(f"/blocks/{batchID}/3")
        ref.set(block_data)
    else:
        safe_filename = evidence.filename.replace(" ", "_").replace("'", "")
        file_ext = safe_filename.split('.')[-1].lower()

        if file_ext == "pdf":
            content_type = "application/pdf"
        elif file_ext in ["jpg", "jpeg"]:
            content_type = "image/jpeg"
        elif file_ext == "png":
            content_type = "image/png"
        else:
            content_type = "application/octet-stream"

        cert_path = f"batches/{batchID}/pharmacy/evidence_{safe_filename}"
        cert_bytes = await evidence.read()
        supabase.storage.from_("cert_upload").upload(cert_path, cert_bytes, file_options={"content-type":content_type})
        evidence_url = supabase.storage.from_("cert_upload").get_public_url(cert_path)
        hashedevidence = hashlib.sha256(cert_bytes).hexdigest()

        ref = db.reference(f"/blocks/{batchID}/2")
        info = ref.get()
        phmID = info.get("data").get("phmID")
        prev_hash = info.get("hash")

        block_data = {
            "data" : {
                "totalQtyreceived" : totalQty,
                "safeQty" : safeQty,
                "damagedQty" : damagedQty,
                "description" : description,
                "phmID" : phmID,
                "deldate" : deldate,
                "files" : {
                    "evidence_url" : evidence_url,
                    "evidencehash" : hashedevidence
                }
            },
            "prev_hash" : prev_hash,
            "timestamp" : datetime.now().strftime("%d-%m-%Y %H:%M:%S.%f")
        }

        encoded_block = json.dumps(block_data, sort_keys=True).encode()
        hash = hashlib.sha256(encoded_block).hexdigest()
        block_data["hash"] = hash

        ref = db.reference(f"/blocks/{batchID}/3")
        ref.set(block_data)
        return RedirectResponse(url = "/pharmacy/history", status_code=303)



    


@app.get("/verify", response_class=HTMLResponse)
async def batchdetails(request : Request):
    return templates.TemplateResponse("qr-verify.html", {"request" : request, "batch" : [],"msg" : ""})
def compute_hash(block_data: dict) -> str:
    
    block_copy = {
        "data": block_data["data"],
        "timestamp": block_data["timestamp"],
        "prev_hash": block_data["prev_hash"]
    }
    encoded = json.dumps(block_copy, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()

def verify_chain(blocks: list) -> int:
    

    if not blocks or len(blocks) == 0:
        return 1  

    for i in range(len(blocks)):
        block = blocks[i]

        recalculated_hash = compute_hash(block)

        if recalculated_hash != block["hash"]:
            if i in [0, 1]:
                return 0        
            elif i == 2:
                return -1       
            elif i >= 3:
                return -2       

        if i > 0:
            prev_block = blocks[i - 1]
            if block["prev_hash"] != prev_block["hash"]:
                if i in [1]:
                    return 0
                elif i == 2:
                    return -1
                elif i >= 3:
                    return -2

    return 1

@app.post("/verify", response_class=HTMLResponse)
async def qrgen(
    request : Request,
    batchID : str = Form(...)
    ):
    ref = db.reference(f"/blocks/{batchID}")
    data = ref.get()
    if (data):

        tamper_code = verify_chain(data)   

        stat = {
            1: "Batch verified successfully. No tampering detected.",
            0: "Tampering detected during manufacturing stage.",
            -1: "Tampering detected during distributor handling.",
            -2: "Tampering detected at pharmacy verification."
        }

        if len(data) == 4:
            if data[3].get("data", {}).get("responsibility"):
                status_msg = "Package was safely transported to pharmacy and no damages were found"
            else:
                status_msg = "Package was damaged before reaching pharmacy"

        elif len(data) == 3 and data[2].get("data", {}).get("notDamaged"):
            status_msg = "Package at distributor, no damages as of now"

        elif len(data) == 2:
            status_msg = "Distributor assigned. Currently at manufacturer"

        elif len(data) == 1:
            status_msg = "Batch created by manufacturer"

        else:
            status_msg = "Unknown batch state"

        final_status = f"{status_msg} {stat[tamper_code]}"

        return templates.TemplateResponse(
            "qr-verify.html",
            {
                "request": request,
                "batch": data,
                "length": len(data),
                "status": final_status,
                "batchID": batchID,
                "msg": "",
                "tamper" : tamper_code
            }
        )

    else:    
        return templates.TemplateResponse("qr-verify.html" , {"request" : request,"batch" : [] ,"msg" : "Batch Not Found"})




@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")

 




