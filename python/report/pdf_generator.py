"""
PDF Report Generator for AgentZero.
Generates publication-quality PDF audit reports from HTML reports using
WeasyPrint or headless Chromium/Edge print-to-pdf.
"""

import os
import subprocess
import shutil
import platform
from typing import Optional


class PDFReportGenerator:
    """Generates PDF reports from AgentZero HTML reports."""

    def __init__(self):
        pass

    def generate(self, html_path: str, output_path: str) -> str:
        """
        Generate a PDF report from an HTML report.
        Tries WeasyPrint first, then headless Chromium / Edge.
        """
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        # 1. Try WeasyPrint
        try:
            from weasyprint import HTML
            HTML(filename=html_path).write_pdf(output_path)
            return output_path
        except ImportError:
            pass
        except Exception:
            pass

        # 2. Try Headless Chrome / Edge CLI
        browser_exec = self._find_browser()
        if browser_exec:
            try:
                cmd = [
                    browser_exec,
                    "--headless",
                    "--disable-gpu",
                    "--no-pdf-header-footer",
                    f"--print-to-pdf={output_path}",
                    f"file://{os.path.abspath(html_path)}"
                ]
                res = subprocess.run(cmd, capture_output=True, timeout=20)
                if res.returncode == 0 and os.path.exists(output_path):
                    return output_path
            except Exception:
                pass

        # 3. Fallback: Copy HTML to output location with note
        fallback_path = output_path.replace(".pdf", ".html")
        shutil.copyfile(html_path, fallback_path)
        return fallback_path

    def _find_browser(self) -> Optional[str]:
        """Locates available Chromium or Edge binary for headless PDF rendering."""
        if platform.system() == "Windows":
            paths = [
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            ]
            for p in paths:
                if os.path.exists(p):
                    return p
        elif platform.system() == "Darwin":
            paths = [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ]
            for p in paths:
                if os.path.exists(p):
                    return p
        else:
            for b in ("google-chrome", "chromium-browser", "chromium", "microsoft-edge"):
                which = shutil.which(b)
                if which:
                    return which
        return None
