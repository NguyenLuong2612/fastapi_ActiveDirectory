import uvicorn
from ad_handle import AD_Handle
from typing import Union
from fastapi import FastAPI
from fastapi import FastAPI, HTTPException
from ldap3 import Connection, Server
from pydantic import BaseModel
app = FastAPI()

class User(BaseModel):
    ho: str
    ten: str
    cmnd: str
    user_dn: str
    department: str
    company: str
    
class Funcs(AD_Handle):
    
    def find_user(self,conn,usrname):
        # usrname, _ = self.info_usr()
        # print(self.find_ad_users(conn,usrname))
        # conn.unbind()
        return self.find_ad_users(conn,usrname)

        
    
### API route

@app.get("/find_user/{username}")
async def api_find_user(username: str):
    
    funcs = Funcs("user1","admin@123")

    # 2 func ldap_connection bỏ qa check tkn ldap_connect_tkn(secure)
    conn = funcs.ldap_connection()

    # Nếu kết nối thành công, tìm kiếm người dùng
    if isinstance(conn, Connection):
        users = await funcs.find_user(conn, username)
        if not users:
            raise HTTPException(status_code=404, detail="User not found")
        return {"users": users}
    else:
        raise HTTPException(status_code=401, detail="Authentication failed")

    
@app.post("/users/")
async def create_item(user: User):
    funcs = Funcs("luongnv","admin@123")
    conn = funcs.ldap_connection()
    if user.company == 'FPTVN':
        ou = 'OU=MyCompany,'
    elif user.company == 'FPTNET':
        ou = 'OU=QuanTri,'
    else:
        ou = 'OU=Partner,'
    return funcs.create_usr(conn,user,ou)


if __name__ == "__main__":
    config = uvicorn.Config("lst_func_copy:app", port=5000, log_level="info")
    server = uvicorn.Server(config)
    server.run()
        

