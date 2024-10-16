from ad_handle import AD_Handle

class Funcs(AD_Handle):
    #########################
    ## Option to implement ##
    #########################
    def __init__(self, LDAP_USER, LDAP_PASSWD):
        super().__init__(LDAP_USER, LDAP_PASSWD)
    
    def create_group(self,conn):
        group_name = str(input('Group name: '))
        description = str(input('Description: '))
        self.ad_create_group(conn, group_name, description,)
    
    def find_user(self,conn,usrdn):
        print(self.find_ad_users(conn,usrdn))
        conn.unbind()
    
    def chekval_usr(self,conn):
        usrname,_ = self.info_usr()
        results = self.chk_PrincipalName(conn,usrname)
        print(results)
        conn.unbind()
        
        
    def info_usr(self):
        ho = str(input('Họ: '))
        ten = str(input('Tên: '))
        user_dn = str(input('UserDomainName: '))
        company = str(input('Company: '))
        department = str(input('Department: '))
        cmnd = str(input('CMND: '))
        if company == 'FPTVN':
            ou = 'OU=MyCompany,'
        elif company == 'FPTNET':
            ou = 'OU=QuanTri,'
        else:
            ou = 'OU=Partner,'
        return ho, ten, cmnd, user_dn, department, company, ou
    
    ## Implement functions    
    def run(self, c):
        # c = self.ldap_connect_tkn()
        #c = self.ldap_connection()
        if c:
            ho, ten, cmnd, user_dn, department, company, ou = self.info_usr()
            # self.create_group(c)
            # self.find_user(c,user_dn)
            # self.create_usr(c,'Nguyen Luong','user@staging.fpt.net')
            self.create_usr(c,ho, ten, cmnd, user_dn, department, company, ou)
            # self.chk_PrincipalName(c, 'user2@staging.fpt.net')
            c.unbind()
        else:
            return
            
if __name__ == "__main__":
    ldapuser = str(input('Tài khoản: '))
    ldappasswd = str(input('Mật khẩu: '))
    funcs = Funcs(ldapuser,ldappasswd)
    conn = funcs.ldap_connect_tkn()
    funcs.run(conn)
    
        

