def deny(start_response, msg):
    ct = 'text/plain'
    cl = str(len(msg))
    start_response('401 Unauthorized',
                   [ ('Content-Type', ct),
                   ('Content-Length', cl) ],
                   )

def allow(start_response, msg):
    ct = 'text/plain'
    cl = str(len(msg))
    start_response('200 OK',
                   [ ('Content-Type', ct),
                   ('Content-Length', cl) ],
                   )
    return [msg]

def app(environ, start_response):
    path_info = environ['PATH_INFO']
    remote_user = environ.get('REMOTE_USER')
    if path_info.endswith('/shared'):
        if not remote_user:
            return deny(start_response, 'You cant do that')
        else:
            return allow(start_response, 'Welcome to the shared area, %s' %
                         remote_user)
    elif path_info.endswith('/admin'):
        if remote_user != 'admin':
            return deny(start_response, 'Only admin can do that')
        else:
            return allow(start_response, 'Hello, admin!')
    elif path_info.endswith('/chris'):
        if remote_user != 'chris':
            return deny(start_response, 'Only chris can do that')
        else:
            return allow(start_response, 'Hello, chris!')
    else:
        return allow(start_response, 'Unprotected page')
    
def make_app(global_config, **kw):
    return app

            
        
            
            
