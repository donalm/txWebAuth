# -*- test-case-name: twisted.web.test.test_httpauth -*-
# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

### MONKEYPATCH

"""
Cleartext form based authentication
"""

from zope.interface import Interface, Attribute
from zope.interface import implementer
from twisted.cred import credentials, error



class IFormCredentialFactory(Interface):
    """
    A credential factory defines a way to generate a particular kind of
    authentication challenge and a way to interpret the responses to these
    challenges.  It creates L{ICredentials} providers from responses.  These
    objects will be used with L{twisted.cred} to authenticate an authorize
    requests.
    """
    scheme = Attribute(
        "A C{str} giving the name of the authentication scheme with which "
        "this factory is associated.  For example, C{'basic'} or C{'digest'}.")


    def getChallenge(request):
        """
        Generate a new challenge to be sent to a client. Same as the existing
        iweb.ICredentialFactory, except that getChallenge should return a URL
        that refers to login form
        """


    def decode(response, request):
        """
        Create a credentials object from the given response.

        @type response: C{str}
        @param response: scheme specific response string

        @type request: L{twisted.web.http.Request}
        @param request: The request being processed (from which the response
            was taken).

        @raise twisted.cred.error.LoginFailed: If the response is invalid.

        @rtype: L{twisted.cred.credentials.ICredentials} provider
        @return: The credentials represented by the given response.
        """



@implementer(IFormCredentialFactory)
class FormCredentialFactory(object):
    """
    Credential Factory for XHTML form authentication

    @type authenticationRealm: C{str}
    @ivar authenticationRealm: The HTTP authentication realm which will be issued in
        challenges.
    """

    scheme = 'myapp'

    def __init__(self, authenticationRealm):
        self.authenticationRealm = authenticationRealm
        self.url = '/%s/login' % (self.scheme,)

    def getChallenge(self, request):
        return self.url

    def decode(self, request):
        """
        Extract the credentials from the POST body. Support
        'decode method so as not to break the interface'
        """

        args = request.args
        try:
            creds = (args['login'][0], args['password'][0])
        except KeyError:
            raise error.LoginFailed('Invalid credentials')
        else:
            return credentials.UsernamePassword(*creds)
