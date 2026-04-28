def resolveDotted(dotted_or_ep):
    """Resolve a dotted name to a callable.
    """
    from repoze.who.resolver import resolve_dotted
    return resolve_dotted(dotted_or_ep)
