"""Escape model- and log-derived text before it is placed into HTML (OWASP LLM05: improper output handling)."""
import html


def esc(text):
    return html.escape(str(text), quote=True)
