from .recon import router as recon_router
from .llm import router as llm_router
from .email import router as email_router
from .automation import router as automation_router

# ── Router objects for main.py ──
recon = recon_router
llm = llm_router
email = email_router
automation = automation_router

__all__ = [
    "recon_router",
    "llm_router",
    "email_router",
    "automation_router",
    "recon",
    "llm",
    "email",
    "automation"
]