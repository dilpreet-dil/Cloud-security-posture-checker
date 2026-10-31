class CollectorError(Exception):
    """Raised when a cloud inventory cannot be collected (credentials, network, etc.)."""


def get_collector(provider: str):
    if provider == "mock":
        from .mock import collect
    elif provider == "aws":
        from .aws import collect
    else:
        raise CollectorError(f"Unsupported provider: {provider}")
    return collect
