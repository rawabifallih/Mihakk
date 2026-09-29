"""Negative controls, loaded only in throwaway test containers.

Each switch disables one behaviour. The production image and checkout are
unchanged; a positive run never mounts this module.
"""

import os

mode = os.environ.get("MIHAKK_TEST_MUTATION", "")
if mode:
    from app import main

    if mode == "from_seq_zero":
        original = main.consume_stream

        async def wrong_resume(*args, **kwargs):
            kwargs["resume_from"] = lambda: 0
            return await original(*args, **kwargs)

        main.consume_stream = wrong_resume
    elif mode == "no_restart_recovery":
        async def no_recovery():
            return []

        main.resume_running_sessions = no_recovery
    elif mode == "mix_sessions":
        original = main.store.Database.append_event
        source = os.environ["MIHAKK_MUTATION_SOURCE"]
        destination = os.environ["MIHAKK_MUTATION_DESTINATION"]

        def cross_store(self, session_id, event):
            return original(self, destination if session_id == source else session_id, event)

        main.store.Database.append_event = cross_store
    elif mode == "leave_running":
        original = main.store.resolve_status

        def wrong_status(engine_status, completeness):
            if engine_status == main.store.INTERRUPTED:
                return main.store.RUNNING
            return original(engine_status, completeness)

        main.store.resolve_status = wrong_status
    else:
        raise RuntimeError("unknown test mutation")
