import importlib


def resolve_dotted(name):
    """Resolve a dotted name in ``module:object`` or ``module.Object`` form."""
    name = name.strip()
    if "[" in name and name.endswith("]"):
        name = name.split("[", 1)[0].rstrip()

    if ":" in name:
        module_name, object_name = name.split(":", 1)
        module_name = module_name.strip()
        object_name = object_name.strip()
        if not module_name or not object_name:
            raise ValueError(f"Invalid dotted name: {name}")
    else:
        try:
            return importlib.import_module(name)
        except ImportError as exc:
            missing_name = getattr(exc, "name", None)
            if missing_name != name:
                raise
        module_name, _, object_name = name.rpartition(".")
        if not module_name:
            raise ImportError(f"Cannot resolve dotted name: {name}")

    module = importlib.import_module(module_name.strip())
    object_name = object_name.strip()
    if not object_name:
        return module

    resolved = module
    for attr in object_name.split("."):
        resolved = getattr(resolved, attr)
    return resolved
