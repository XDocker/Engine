from .amazon import AmazonProvider
from .base import registry

providers = [
        'AmazonProvider'
        ]

for pr in providers:
    cl = locals()[pr]
    registry[cl.provider_name] = cl


__all__ = [
        'registry'
        ] + providers
