"""Public, synthetic, opt-in Agave fixture. Importing never starts a node."""
from .bridge import create_bridge

__all__ = ['create_bridge']
