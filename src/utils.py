import os


def cls():
    print("\033c", end="")


def to_os_path(path: str) -> str:
    """Convert a path to an OS-specific path."""
    if os.name == "nt":
        return path.replace("/", "\\")
    if path.startswith("C:\\"):  # USer on WSL
        return path.replace("C:\\", "/mnt/c/").replace("\\", "/")
    return path
