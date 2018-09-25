import os

from zope import interface

from twisted.application import internet, service
from twisted.cred import checkers, portal
from twisted.python import log
from twisted.web import resource, server, static
import credfactory, wrapper


class Simple(resource.Resource):
    isLeaf = True
    def __init__(self, username):
        resource.Resource.__init__(self)
        self.username = username

    def render(self, *args, **kwargs):
        return resource.Resource.render(self, *args, **kwargs)

    def render_POST(self, request):
        return "<html>assembly_elements.tac :: %s</html>" % (self.username,)

    def render_GET(self, request):
        return "<html>assembly_elements.tac :: %s</html>" % (self.username,)





def logout():
    """
    A simple do-nothing placeholder for logout behavior.
    """

    log.msg('logout called.')
    return None

def sessionExpired(session):
    log.msg('session expired.')
    session.avatar = None


class WebAuthSession(server.Session):
    sessionTimeout = 3600

    def __init__(self, site, uid, reactor=None):
        server.Session.__init__(self, site, uid, reactor)
        self.avatar = None



@interface.implementer(portal.IRealm)
class WebAuthenticatedRealm(object):

    def __init__(self, anonymousRoot, authorizedRoot):
        self.anonymousRoot = anonymousRoot
        self.authorizedRoot = authorizedRoot

    def requestAvatar(self, avatarId, request, *interfaces):
        """
        Called after the user has successfully authenticated, returning an
        IResource instance representing the user's HTTP interface to an app.
        """

        if resource.IResource in interfaces:
            session = request.getSession()
            if avatarId is checkers.ANONYMOUS:
                log.msg('Anonymous')
                return (resource.IResource, self.anonymousRoot(), logout)
            else:
                log.msg('Authenticated: ' + avatarId)
                avatar = self.authorizedRoot(avatarId)
                session.avatar = avatar
                if not session.expireCallbacks:
                    session.notifyOnExpire(lambda: sessionExpired(session))
                return (
                    resource.IResource,
                    avatar,
                    logout
                )
        log.msg('requestAvatar: Realm not implemented.')
        raise NotImplementedError()



credentialFactories = [credfactory.FormCredentialFactory("myapp")]

def authorizedResource(*args, **kw):
    avatar = resource.Resource()
    avatar.putChild('myapp', Simple(*args, **kw))
    return avatar

root = wrapper.WebAuthSessionWrapper(
    portal.Portal(
        WebAuthenticatedRealm(wrapper.UnauthorizedResource, authorizedResource), #static.File
        [
            checkers.AllowAnonymousAccess(),
            checkers.InMemoryUsernamePasswordDatabaseDontUse(**{'jbernier': 'letmein', 'ldb': 'letmein'})
            #checkers.FilePasswordDB('httpd.password')
        ]
    ),
    credentialFactories
)


def getWebService():
    """Return a service suitable for creating an application object. """
    site = server.Site(root)
    site.sessionFactory = WebAuthSession
    return internet.TCPServer(9000, site)

application = service.Application("FormAuthDemo")
service = getWebService()
service.setServiceParent(application)
