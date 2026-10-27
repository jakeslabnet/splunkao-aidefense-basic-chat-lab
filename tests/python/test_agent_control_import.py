"""SDK preparation must not activate controls or a second telemetry pipeline."""

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap


def test_runtime_imports_agent_control_without_initialization_or_side_effects():
    script = textwrap.dedent("""
        import json
        import socket
        import threading
        from importlib.metadata import version
        from opentelemetry import trace

        provider = trace.get_tracer_provider()
        threads = {thread.ident for thread in threading.enumerate()}
        network_attempts = []

        def denied(*args, **kwargs):
            network_attempts.append(True)
            raise AssertionError('Runtime imports must not access the network')

        socket.socket.connect = denied
        socket.socket.connect_ex = denied
        socket.getaddrinfo = denied

        import agent_control
        assert agent_control.current_agent() is None

        def init_denied(*args, **kwargs):
            raise AssertionError('Agent Control must remain uninitialized')

        agent_control.init = init_denied
        import main

        assert main.agent_control is agent_control
        assert agent_control.current_agent() is None
        assert trace.get_tracer_provider() is provider
        assert {thread.ident for thread in threading.enumerate()} == threads
        assert network_attempts == []
        print(json.dumps({'sdkVersion': version('agent-control-sdk'),
                          'initialized': False, 'networkAttempts': 0,
                          'newThreads': 0, 'sameTracerProvider': True}))
    """)
    environment = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2] / "agent"),
                   "AWS_EC2_METADATA_DISABLED": "true"}
    result = subprocess.run([sys.executable, "-c", script], env=environment,
                            capture_output=True, text=True, check=True, timeout=30)
    evidence = json.loads(result.stdout)
    assert evidence["sdkVersion"] == "8.14.0"
    assert evidence["initialized"] is False
    assert evidence["networkAttempts"] == evidence["newThreads"] == 0
    assert evidence["sameTracerProvider"] is True
