from .server import serve, serve_http

def main():
    """MCP WinDbg Server - Windows crash dump analysis functionality for MCP"""
    import argparse
    import asyncio
    import logging
    import os
    import sys

    parser = argparse.ArgumentParser(
        description="Give a model the ability to analyze Windows crash dumps with WinDbg/CDB"
    )
    parser.add_argument("--cdb-path", type=str, help="Custom path to cdb.exe")
    parser.add_argument("--symbols-path", type=str, help="Custom symbols path")
    parser.add_argument("--timeout", type=int, default=240, help="Command timeout in seconds (default: 240)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--log-file", type=str, help="Path to log file for debug output")

    # Transport options
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport protocol to use (default: stdio)"
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind HTTP server to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind HTTP server to (default: 8000)")

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    handlers = []

    # If log file is specified, log to file
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, mode='a')
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
    elif args.verbose:
        # For verbose without log file, use a default log file location
        # (can't use stderr for stdio transport as it interferes with MCP)
        default_log_path = os.path.join(os.environ.get('TEMP', os.environ.get('TMP', '.')), 'mcp-windbg.log')
        file_handler = logging.FileHandler(default_log_path, mode='a')
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter(log_format))
        handlers.append(file_handler)
        print(f"Logging to: {default_log_path}", file=sys.stderr)

    if handlers:
        logging.basicConfig(level=log_level, handlers=handlers, format=log_format)
        # Also set level for our specific modules
        logging.getLogger('mcp_windbg').setLevel(log_level)
        logging.getLogger('mcp_windbg.server').setLevel(log_level)
        logging.getLogger('mcp_windbg.cdb_session').setLevel(log_level)

    if args.transport == "stdio":
        asyncio.run(serve(
            cdb_path=args.cdb_path,
            symbols_path=args.symbols_path,
            timeout=args.timeout,
            verbose=args.verbose
        ))
    else:
        asyncio.run(serve_http(
            host=args.host,
            port=args.port,
            cdb_path=args.cdb_path,
            symbols_path=args.symbols_path,
            timeout=args.timeout,
            verbose=args.verbose
        ))


if __name__ == "__main__":
    main()
