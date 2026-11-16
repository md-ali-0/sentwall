"""VulnScope - automated web security assessment toolkit."""

__version__ = "1.0.0"
__all__ = ["__version__"]

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass
