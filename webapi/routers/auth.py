from fastapi import APIRouter, Depends, Response
from webapi.schemas import LoginIn, MfaVerifyIn, MfaCodeIn
from webapi.core.security import begin_login, complete_mfa_login, current_user, csrf_protect, set_session_cookies, clear_session_cookies, setup_mfa, enable_mfa, disable_mfa
router=APIRouter(prefix='/auth',tags=['Auth'])

@router.post('/login')
def sign_in(body:LoginIn,response:Response):
    result=begin_login(body.username,body.password)
    if result.get('mfa_required'):
        return result
    csrf=set_session_cookies(response,result.pop('token'))
    result['csrf_token']=csrf
    return result

@router.post('/mfa/verify')
def mfa_verify(body:MfaVerifyIn,response:Response):
    result=complete_mfa_login(body.challenge,body.code)
    csrf=set_session_cookies(response,result.pop('token'))
    result['mfa_required']=False; result['csrf_token']=csrf
    return result

@router.post('/logout')
def logout(response:Response,user=Depends(csrf_protect)):
    clear_session_cookies(response); return {'ok':True}

@router.get('/me')
def me(user=Depends(current_user)):
    user=dict(user); user.pop('_auth_type',None); return user

@router.post('/mfa/setup')
def mfa_setup(user=Depends(csrf_protect)): return setup_mfa(user)

@router.post('/mfa/enable')
def mfa_enable(body:MfaCodeIn,user=Depends(csrf_protect)):
    enable_mfa(user,body.code); return {'ok':True}

@router.post('/mfa/disable')
def mfa_disable(body:MfaCodeIn,user=Depends(csrf_protect)):
    disable_mfa(user,body.code); return {'ok':True}
