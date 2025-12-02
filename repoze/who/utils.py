def resolveDotted(dotted_or_ep):
    """ Resolve a dotted name or setuptools entry point to a callable.
    """
    from importlib.metadata import EntryPoint
    return EntryPoint.parse('x=%s' % dotted_or_ep).resolve()
