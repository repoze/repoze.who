""" Configuration parser
"""
from ConfigParser import ConfigParser
from StringIO import StringIO
from pkg_resources import EntryPoint

from repoze.who.interfaces import IChallengeDecider
from repoze.who.interfaces import IRequestClassifier

def _resolve(name):
    if name:
        return EntryPoint.parse('x=%s' % name).load(False)

def _isClassOrType(obj):
    return type(obj) in (type(WhoConfig), type)

class WhoConfig:
    def __init__(self):
        self.request_classifier = None
        self.challenge_decider = None
        self.plugins = {}
        self.identifiers = []
        self.authenticators = []
        self.challengers = []
        self.mdproviders = []

    def _getPlugin(self, name):
        obj = self.plugins.get(name)
        if obj is None:
            obj = _resolve(name)
            if _isClassOrType(obj):
                obj = obj()
        return obj

    def _parsePluginSequence(self, attr, proptext):
        lines = proptext.split()
        for line in lines:
            if ';' in line:
                plugin_name, classifier = line.split(';')
            else:
                plugin_name = line
                classifier = None
            attr.append({'plugin': self._getPlugin(plugin_name),
                         'classifier': classifier
                        })

    def parse(self, text):
        if getattr(text, 'readline', None) is None:
            text = StringIO(text)
        cp = ConfigParser()
        cp.readfp(text)

        for s_id in [x for x in cp.sections() if x.startswith('plugin:')]:
            plugin_id = s_id[len('plugin:'):]
            options = dict(cp.items(s_id))
            if 'use' in options:
                obj = _resolve(options['use'])
                if _isClassOrType(obj):
                    del options['use']
                    obj = obj(**options)
                self.plugins[plugin_id] = obj

        if 'general' in cp.sections():
            general = dict(cp.items('general'))

            rc = general.get('request_classifier')
            self.request_classifier = self._getPlugin(rc)

            cd = general.get('challenge_decider')
            self.challenge_decider = self._getPlugin(cd)

        if 'identifiers' in cp.sections():
            identifiers = dict(cp.items('identifiers'))
            self._parsePluginSequence(self.identifiers,
                                      identifiers['plugins'])

        if 'authenticators' in cp.sections():
            authenticators = dict(cp.items('authenticators'))
            self._parsePluginSequence(self.authenticators,
                                      authenticators['plugins'])

        if 'challengers' in cp.sections():
            challengers = dict(cp.items('challengers'))
            self._parsePluginSequence(self.challengers,
                                      challengers['plugins'])

        if 'mdproviders' in cp.sections():
            mdproviders = dict(cp.items('mdproviders'))
            self._parsePluginSequence(self.mdproviders,
                                      mdproviders['plugins'])
