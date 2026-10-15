"""Shared guest-side code: the wire codec, Blue's policy, the LLM stand-in.

Copied into each MicroVM rootfs by `microvm/build_immutable_images.sh`; guests
have no package index and no network, so nothing here may import a third-party
module.
"""

from . import engine, policy, wire

__all__ = ["engine", "policy", "wire"]
