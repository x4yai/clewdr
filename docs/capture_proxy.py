#!/usr/bin/env python3
"""
Transparent HTTP capture proxy for Claude Code CLI request analysis.

Chain: Claude Code CLI → [this proxy :9999] → model-family :3000

Captures full headers + body, supports SSE streaming responses.
"""

import http.server
import http.client
import json
import os
import sys
import time
import gzip
import socket
from datetime import datetime
from urllib.parse import urlparse

LISTEN_PORT = 9999
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 3000  # model-family
CAPTURE_DIR = "/tmp/claude_captures"

os.makedirs(CAPTURE_DIR, exist_ok=True)

capture_count = 0


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self._handle_request("POST")

    def do_GET(self):
        self._handle_request("GET")

    def do_OPTIONS(self):
        self._handle_request("OPTIONS")

    def _handle_request(self, method):
        global capture_count
        capture_count += 1
        cap_id = capture_count
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = f"{CAPTURE_DIR}/cap_{ts}_{cap_id}"

        # --- Capture incoming request ---
        path = self.path
        headers_dict = {}
        for key in self.headers:
            headers_dict[key] = self.headers[key]

        content_length = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(content_length) if content_length > 0 else b""

        # Decompress if gzipped
        if body_raw and self.headers.get("Content-Encoding") == "gzip":
            try:
                body_raw = gzip.decompress(body_raw)
            except:
                pass

        body_text = ""
        body_json = None
        if body_raw:
            try:
                body_text = body_raw.decode("utf-8")
                body_json = json.loads(body_text)
            except:
                body_text = body_raw.decode("utf-8", errors="replace")

        # Save captured request
        capture = {
            "capture_id": cap_id,
            "timestamp": ts,
            "method": method,
            "path": path,
            "headers": headers_dict,
            "headers_count": len(headers_dict),
            "body_length": len(body_raw),
        }

        with open(f"{prefix}_request_headers.json", "w") as f:
            json.dump(capture, f, indent=2, ensure_ascii=False)

        if body_json:
            with open(f"{prefix}_request_body.json", "w") as f:
                json.dump(body_json, f, indent=2, ensure_ascii=False)
            analysis = analyze_body(body_json)
            with open(f"{prefix}_request_analysis.json", "w") as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False)
        elif body_text:
            with open(f"{prefix}_request_body.txt", "w") as f:
                f.write(body_text)

        # Print console summary
        print(f"\n{'='*70}")
        print(f"  [#{cap_id}] {method} {path}")
        print(f"  Time: {ts}")
        print(f"  Headers ({len(headers_dict)}):")
        for k, v in sorted(headers_dict.items()):
            v_display = str(v) if len(str(v)) < 100 else str(v)[:100] + "..."
            print(f"    {k}: {v_display}")
        if body_json:
            print(f"  Body: JSON, {len(body_raw)} bytes")
            print(f"  Top-level keys (ordered): {list(body_json.keys())}")
            if "model" in body_json:
                print(f"    model: {body_json['model']}")
            if "max_tokens" in body_json:
                print(f"    max_tokens: {body_json['max_tokens']}")
            if "stream" in body_json:
                print(f"    stream: {body_json['stream']}")
            if "thinking" in body_json:
                print(f"    thinking: {json.dumps(body_json['thinking'])}")
            if "metadata" in body_json:
                print(f"    metadata: {json.dumps(body_json['metadata'], ensure_ascii=False)[:300]}")
            if "context_management" in body_json:
                print(f"    context_management: {json.dumps(body_json['context_management'])}")
            if "system" in body_json and isinstance(body_json["system"], list):
                print(f"    system: {len(body_json['system'])} blocks")
                for i, b in enumerate(body_json["system"]):
                    if isinstance(b, dict):
                        print(f"      [{i}] type={b.get('type')}, len={len(b.get('text',''))}, cache={b.get('cache_control')}")
            if "messages" in body_json:
                print(f"    messages: {len(body_json['messages'])}")
            if "tools" in body_json:
                print(f"    tools: {len(body_json['tools'])}")
        print(f"  Files: {prefix}_*")
        print(f"{'='*70}")
        sys.stdout.flush()

        # --- Forward to upstream ---
        try:
            conn = http.client.HTTPConnection(UPSTREAM_HOST, UPSTREAM_PORT, timeout=620)
            # Build headers for upstream
            fwd_headers = {}
            for key, value in headers_dict.items():
                lk = key.lower()
                if lk in ("host", "transfer-encoding"):
                    continue
                fwd_headers[key] = value
            fwd_headers["Host"] = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
            fwd_headers["Content-Length"] = str(len(body_raw))

            conn.request(method, path, body=body_raw, headers=fwd_headers)
            resp = conn.getresponse()

            # Send response back to client
            self.send_response_only(resp.status)
            # Collect response headers
            resp_headers = {}
            for key, value in resp.getheaders():
                lk = key.lower()
                if lk in ("transfer-encoding",):
                    continue
                resp_headers[key] = value
                self.send_header(key, value)
            # Force chunked for streaming
            is_stream = resp_headers.get("content-type", "").startswith("text/event-stream")
            if is_stream:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            # Stream response body
            resp_body_parts = []
            total_bytes = 0
            if is_stream:
                # SSE streaming - read and forward chunks
                while True:
                    chunk = resp.read(4096)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    resp_body_parts.append(chunk)
                    # Send as chunked encoding
                    self.wfile.write(f"{len(chunk):x}\r\n".encode())
                    self.wfile.write(chunk)
                    self.wfile.write(b"\r\n")
                    self.wfile.flush()
                # End chunked response
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            else:
                # Non-streaming - read all and forward
                body = resp.read()
                total_bytes = len(body)
                resp_body_parts.append(body)
                self.wfile.write(body)
                self.wfile.flush()

            # Save first part of response
            resp_preview = b"".join(resp_body_parts[:5])
            with open(f"{prefix}_response_info.json", "w") as f:
                json.dump({
                    "status": resp.status,
                    "headers": resp_headers,
                    "body_total_bytes": total_bytes,
                    "is_stream": is_stream,
                    "body_preview": resp_preview[:2000].decode("utf-8", errors="replace"),
                }, f, indent=2, ensure_ascii=False)

            print(f"  → Response: {resp.status}, {total_bytes} bytes, stream={is_stream}")
            sys.stdout.flush()

            conn.close()

        except Exception as e:
            print(f"  [ERROR] {e}")
            import traceback
            traceback.print_exc()
            sys.stdout.flush()
            try:
                self.send_error(502, str(e))
            except:
                pass

    def log_message(self, format, *args):
        pass


def analyze_body(body):
    """Deep analysis of request body structure."""
    analysis = {
        "top_level_key_order": list(body.keys()),
        "field_types": {k: type(v).__name__ for k, v in body.items()},
    }

    if "model" in body:
        analysis["model"] = body["model"]

    if "thinking" in body:
        analysis["thinking"] = body["thinking"]

    if "max_tokens" in body:
        analysis["max_tokens"] = body["max_tokens"]

    if "metadata" in body:
        meta = body["metadata"]
        analysis["metadata_raw"] = meta
        if "user_id" in meta and isinstance(meta["user_id"], str):
            try:
                analysis["metadata_user_id_parsed"] = json.loads(meta["user_id"])
            except:
                pass

    if "context_management" in body:
        analysis["context_management"] = body["context_management"]

    if "system" in body and isinstance(body["system"], list):
        analysis["system_block_count"] = len(body["system"])
        analysis["system_blocks_summary"] = []
        for i, block in enumerate(body["system"]):
            if isinstance(block, dict):
                info = {
                    "index": i,
                    "type": block.get("type"),
                    "text_length": len(block.get("text", "")),
                    "cache_control": block.get("cache_control"),
                    "text_first_100": block.get("text", "")[:100],
                }
                analysis["system_blocks_summary"].append(info)

    if "messages" in body:
        msgs = body["messages"]
        analysis["message_count"] = len(msgs)
        msg_summary = []
        for i, msg in enumerate(msgs):
            info = {"index": i, "role": msg.get("role")}
            content = msg.get("content", "")
            if isinstance(content, list):
                info["content_format"] = "array"
                info["block_count"] = len(content)
                blocks = []
                for j, b in enumerate(content):
                    if isinstance(b, dict):
                        bi = {"index": j, "type": b.get("type"), "cache_control": b.get("cache_control")}
                        if "text" in b:
                            bi["text_length"] = len(b["text"])
                        blocks.append(bi)
                info["blocks"] = blocks
            else:
                info["content_format"] = "string"
                info["text_length"] = len(str(content))
            msg_summary.append(info)
        analysis["messages_summary"] = msg_summary

    if "tools" in body:
        analysis["tool_count"] = len(body["tools"])
        analysis["tool_names"] = [t.get("name", "?") for t in body["tools"] if isinstance(t, dict)]

    optional_fields = [
        "temperature", "top_k", "top_p", "stop_sequences",
        "tool_choice", "context_management", "metadata",
        "n", "container", "mcp_servers", "output_config",
        "output_format", "service_tier"
    ]
    analysis["optional_present"] = [f for f in optional_fields if f in body]
    analysis["optional_absent"] = [f for f in optional_fields if f not in body]

    return analysis


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else LISTEN_PORT
    upstream = sys.argv[2] if len(sys.argv) > 2 else f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
    if ":" in upstream:
        parts = upstream.split(":")
        UPSTREAM_HOST = parts[0]
        UPSTREAM_PORT = int(parts[1])

    print(f"=== Claude Code CLI Capture Proxy ===")
    print(f"Listen:   http://127.0.0.1:{port}")
    print(f"Upstream: http://{UPSTREAM_HOST}:{UPSTREAM_PORT}")
    print(f"Captures: {CAPTURE_DIR}/")
    print()
    print(f"Usage: ANTHROPIC_BASE_URL=http://127.0.0.1:{port} claude ...")
    print()

    server = http.server.HTTPServer(("127.0.0.1", port), CaptureHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nProxy stopped.")
        server.shutdown()
