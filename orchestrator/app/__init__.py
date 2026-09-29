"""Mihakk orchestrator: sessions, storage, analysis and reports.

This service never contacts a target. It talks to the engine's control API
and nothing else; the engine owns scope checking, address pinning, the limits
and the kill switch. Keeping the two apart is what stops the orchestrator
becoming a second, unguarded way to send traffic.
"""
