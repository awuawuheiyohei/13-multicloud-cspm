"""MultiCloud CSPM CIS Compliance-as-Code - FastAPI 入口（端口 5040）"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="MultiCloud CSPM CIS Compliance-as-Code", version="0.1.0")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
STATIC_DIR.mkdir(exist_ok=True)


@app.on_event("startup")
def _startup():
    from .models.db import init_db
    init_db()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "cspm-cis", "version": "0.1.0"}


# 业务路由
from .api.routes import router as api_router  # noqa: E402
app.include_router(api_router, prefix="/api")


# 静态 Dashboard（5 tab Vanilla JS）
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


def run():
    import uvicorn
    import os
    port = int(os.environ.get("WEB_PORT", "5040"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    run()
