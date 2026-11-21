#!/usr/bin/env python3
"""Exercise the macOS downloader on loopback, with no kit install or network downloads."""
import http.server
import pathlib
import random
import re
import subprocess
import tempfile
import threading
import unittest

MAC = pathlib.Path(__file__).resolve().parents[1]
HELPER = MAC / "Resources/nullmoth-download.sh"
BASH = "/bin/bash"
CHUNK = 1024 * 1024


class RangeServer(http.server.ThreadingHTTPServer):
    request_queue_size = 128

    def __init__(self, payload, workers):
        super().__init__(("127.0.0.1", 0), RangeHandler)
        self.payload = payload
        self.workers = workers
        self.active = self.peak = 0
        self.requests = []
        self.lock = threading.Lock()
        self.all_started = threading.Event()
        self.release = threading.Event()


class RangeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        server = self.server
        payload = memoryview(server.payload)
        size = len(payload)
        header = self.headers.get("Range")
        with server.lock:
            server.requests.append(header)
        match = re.fullmatch(r"bytes=(\d+)-(\d*)", header or "")
        partial = match is not None and self.path != "/ignore"
        if partial:
            start = int(match[1])
            end = int(match[2]) if match[2] else size - 1
        else:
            start, end = 0, size - 1
        hold = partial and start < end and self.path == "/parallel"
        if hold:
            with server.lock:
                server.active += 1
                server.peak = max(server.peak, server.active)
                if server.active == server.workers:
                    server.all_started.set()
            server.release.wait(timeout=10)
        try:
            self.send_response(206 if partial else 200)
            if partial:
                # Reject exactly one segment while keeping the first and any serial resume valid.
                bad = self.path == "/wrong" and start == size // server.workers and bool(match[2])
                self.send_header("Content-Range", f"bytes {start + bad}-{end}/{size}")
            self.send_header("Content-Length", str(end - start + 1))
            self.end_headers()
            self.wfile.write(payload[start:end + 1])
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if hold:
                with server.lock:
                    server.active -= 1


class ParallelDownloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpu_count = int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.logicalcpu"]))
        cls.payload = random.Random(2026).randbytes(36 * CHUNK + 127)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = pathlib.Path(self.temporary.name)
        self.dest = self.folder / "archive file"
        self.workers = min(self.cpu_count, (len(self.payload) + CHUNK - 1) // CHUNK)
        self.server = RangeServer(self.payload, self.workers)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def command(self, endpoint):
        url = f"http://127.0.0.1:{self.server.server_port}/{endpoint}"
        return [
            BASH, "-uc", '. "$1"; shift; nm_download "$1" "$2" "$3" =http -fsSL -C - '
            '--proto =http --proto-redir =http --noproxy "*" --max-time 12 -o "$2" "$1"',
            "download-test", str(HELPER), url, str(self.dest), str(len(self.payload)),
        ]

    def assert_downloaded(self):
        self.assertEqual(self.dest.read_bytes(), self.payload)
        self.assertEqual(list(self.folder.glob(".download.*")), [])

    def test_uses_available_logical_cpus_and_locks_the_prefix(self):
        if self.workers < 2:
            self.skipTest("parallelism requires multiple logical CPUs")
        first = subprocess.Popen(self.command("parallel"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(self.server.all_started.wait(timeout=10), f"peak {self.server.peak}, expected {self.workers}")
            second = subprocess.run(self.command("parallel"), capture_output=True, text=True, timeout=5)
            self.assertEqual(second.returncode, 75, second.stderr)
        finally:
            self.server.release.set()
            out, err = first.communicate(timeout=20)
        self.assertEqual(first.returncode, 0, out + err)
        self.assertIn(f"up to {self.cpu_count} parallel connections", out)
        self.assertEqual(self.server.peak, self.workers)
        self.assert_downloaded()

    def test_without_ranges_restarts_an_existing_short_prefix(self):
        prefix = CHUNK + 127
        self.dest.write_bytes(self.payload[:prefix])
        result = subprocess.run(self.command("ignore"), capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("continuing with one connection", result.stdout)
        self.assertEqual(self.server.requests, [f"bytes={prefix}-{prefix}", None])
        self.assert_downloaded()

    def test_invalid_range_falls_back_from_the_last_valid_byte(self):
        if self.workers < 2:
            self.skipTest("parallelism requires multiple logical CPUs")
        result = subprocess.run(self.command("wrong"), capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("continuing with one connection", result.stdout)
        self.assertIn(f"bytes={len(self.payload) // self.workers}-", self.server.requests)
        self.assert_downloaded()

    def test_pinned_kit_resume_commands_use_the_adapter(self):
        kit = MAC.parent / "kit/laydown"
        golden_gate = (MAC / "Resources/nullmoth-golden-gate.sh").read_text()
        runner = golden_gate.split("run_kit_program() {", 1)[1].split("\n}", 1)[0]
        command = 'HERE=$1; shift; run_kit_program() {' + runner + '\n}; run_kit_program "$@"'
        for name, kind in (("lay-down-27.sh", "IPSW"), ("make-kernel-collections.sh", "KDK")):
            with self.subTest(script=name):
                source = (kit / name).read_text()
                curl = re.search(r'(?m)^ *curl -sS -f -L -C - .*?; rc=\$\?', source, re.DOTALL)[0]
                script = self.folder / name
                script.write_text(
                    f'{kind}_URL=https://example.invalid/image\n{kind}_SIZE=99999999\n'
                    f'{kind}="a path with spaces"\n'
                    'nm_download() { printf "%s %s %s %s\n" "$1" "$2" "$3" "$4"; }\n'
                    + curl + '\nexit "$rc"\n'
                )
                result = subprocess.run(
                    [BASH, "-uc", command, "adapter-test", str(HELPER.parent), str(script), "--apply"],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "https://example.invalid/image a path with spaces 99999999 =https")


if __name__ == "__main__":
    unittest.main()
