from importlib.metadata import EntryPoint


class InvalidDottedName(ValueError):
    def __init__(self, name):
        self.name = name
        super().__init__(f"Invalid dotted name: {name}")


def resolveDotted(dotted_or_ep):
    """Resolve a standard ``module:object`` reference to a callable."""
    name = dotted_or_ep.strip()

    if ":" not in name or "[" in name or "]" in name:
        raise InvalidDottedName(name)

    module_name, object_name = name.split(":", 1)

    if not module_name.strip() or not object_name.strip():
        raise InvalidDottedName(name)

    return EntryPoint(name="x", value=name, group="x").load()
