"""Create explicitly enrolled test administrators; no production authentication bypass."""
from vpn_auth import totp

def enroll(store, username='owner', password='test-management-password', role='owner', actor='console-bootstrap'):
    record=store.create_admin(username,password,role,actor)
    codes=store.enroll(record['enrollment'],totp(record['secret'],int(store.clock()//30)))
    session,csrf=store.login(password,username=username,code=codes[0])
    return record['id'],session,csrf,codes
