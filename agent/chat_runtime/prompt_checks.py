"""Run independent observation checks before a model call without enforcing them."""

import asyncio

from strands.hooks import AfterModelCallEvent, BeforeModelCallEvent, HookProvider, HookRegistry

from .diagnostics import diagnostic, safe_error_code


class ParallelPromptMonitor(HookProvider):
    def __init__(self, cisco, splunk_control):
        self.cisco = cisco
        self.splunk_control = splunk_control

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeModelCallEvent, self.before_model)
        registry.add_callback(AfterModelCallEvent, self.cisco.after_model)

    async def before_model(self, event: BeforeModelCallEvent) -> None:
        # Both services inspect the original dialogue before generation starts.
        # A failure in either optional check cannot suppress the other check.
        results = await asyncio.gather(
            self.cisco.before_model(event), self.splunk_control.before_model(event),
            return_exceptions=True,
        )
        for integration, monitor, result in zip(
            ("cisco", "splunk_control"), (self.cisco, self.splunk_control), results,
        ):
            if isinstance(result, asyncio.CancelledError):
                raise result
            if isinstance(result, Exception):
                monitor.status = "error"
                diagnostic("integration_error", monitor.request.request_id,
                           integration=integration, phase="input", status="error",
                           errorCode=safe_error_code(result))
        # Observation never sets event.cancel, rewrites messages, or retries.
