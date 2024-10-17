import uvicorn
from ad_handle import AD_Handle
from fastapi import FastAPI, HTTPException, Depends, Query, Body, Form
from ldap3 import Connection, Server
from pydantic import BaseModel, Field
from typing import Annotated
import pandas as pd
from fastapi import FastAPI, UploadFile
from io import StringIO
from fastapi.security import OAuth2PasswordBearer

app = FastAPI()

class UserBase():
    ho: str = Field(min_length=1)
    ten: str = Field(min_length=1)
    cmnd: str = Field(min_length=9,max_length=12,pattern=r'^[0-9]')
    user_dn: str = Field(pattern=r'^[a-zA-Z0-9._%]+@(staging\.fpt\.net)$')
    department: str = Field(min_length=1)
    company: str = Field(min_length=1)
    model_config = {"extra": "forbid"}
    
    
class User(BaseModel,UserBase):
    pass


class Funcs(AD_Handle):
    
    def find_user(self,conn,usrname):
        # usrname, _ = self.info_usr()
        # print(self.find_ad_users(conn,usrname))
        # conn.unbind()
        return self.find_ad_users(conn,usrname)

        
    
### API route
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/token/")
async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"token": token}

@app.get("/find_user/{username}")
async def api_find_user(username: str):
    funcs = Funcs("user1","admin@123")
    # 2 func ldap_connection bỏ qa check tkn ldap_connect_tkn(secure)
    conn = funcs.ldap_connection()
    if isinstance(conn, Connection):
        users = await funcs.find_user(conn, username)
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        return {"users": users}
    else:
        raise HTTPException(status_code=503, detail="LDAP server is not connected.")

    
@app.post("/create_users/")
async def create_users(user: Annotated[User,Form()]):
    funcs = Funcs("luongnv","admin@123")
    conn = funcs.ldap_connection()
    if isinstance(conn, Connection):
        if user.company == 'FPTVN':
            ou = 'OU=MyCompany,'
        elif user.company == 'FPTNET':
            ou = 'OU=QuanTri,'
        else:
            ou = 'OU=Partner,'
        return funcs.create_usr(conn,user,ou)
    else:
        raise HTTPException(status_code=503, detail="LDAP server is not connected.")

@app.post("/uploadfile/")
async def create_upload_file(file: UploadFile):
    contents = await file.read()  # Đọc file thành bytes
    funcs = Funcs("user1","admin@123")
    conn = funcs.ldap_connection()
    user = UserBase
    
    # Chuyển bytes thành chuỗi với các ký tự không hợp lệ được thay thế
    decoded_contents = contents.decode("utf-8", errors="replace")

    # Đọc file CSV từ chuỗi đã được giải mã
    df = pd.read_csv(StringIO(decoded_contents),encoding='utf-8')

    # Trả về nội dung DataFrame dưới dạng JSON
    datas = df.to_dict(orient="records")
    for data in datas:
        user.ho = data.get("Họ")
        user.ten = data.get("Tên")
        user.cmnd = data.get("CMND")
        user.user_dn = data.get("UserDomain")
        user.department = data.get("Phòng Ban")
        user.company = data.get("Công Ty")
        if isinstance(conn, Connection):
            if user.company == 'FPTVN':
                ou = 'OU=MyCompany,'
            elif user.company == 'FPTNET':
                ou = 'OU=QuanTri,'
            else:
                ou = 'OU=Partner,'
            funcs.create_usr(conn,user,ou)
        else:
            raise HTTPException(status_code=503, detail="LDAP server is not connected.")
    return datas

if __name__ == "__main__":
    config = uvicorn.Config("lst_func_copy:app", port=5000, log_level="info")
    server = uvicorn.Server(config)
    server.run()
        

