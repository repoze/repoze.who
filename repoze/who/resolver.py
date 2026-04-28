from importlib.metadata import EntryPoint


def resolve_dotted(name):
    """Resolve a standard ``module:object`` reference to a callable."""
    name = name.strip()
    if ":" not in name or "[" in name or "]" in name:
        raise ValueError(f"Invalid dotted name: {name}")
    module_name, object_name = name.split(":", 1)
    if not module_name.strip() or not object_name.strip():
        raise ValueError(f"Invalid dotted name: {name}")
    return EntryPoint(name="x", value=name, group="x").load()
