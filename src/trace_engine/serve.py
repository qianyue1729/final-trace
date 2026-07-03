"""服务入口：python -m trace_engine.serve [--config path] [--port N]"""
from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="trace-engine 告警溯源服务")
    parser.add_argument("--config", default=None, help="YAML/JSON 配置文件路径")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    from .config import EngineConfig
    from .service.app import create_app

    cfg = EngineConfig.load(args.config)
    if args.host:
        cfg.service.host = args.host
    if args.port:
        cfg.service.port = args.port

    app = create_app(cfg)

    import uvicorn
    uvicorn.run(app, host=cfg.service.host, port=cfg.service.port, log_level="info")


if __name__ == "__main__":
    main()
