from __future__ import annotations

import logging
import shutil
import subprocess
from typing import List

logger = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    def __init__(self, tool: str):
        self.tool = tool
        super().__init__(f"Required tool not found: '{tool}'. Please install it and ensure it's in your PATH.")


class ToolTimeoutError(Exception):
    pass


def check_tool(tool: str) -> str:
    path = shutil.which(tool)
    if path is None:
        raise ToolNotFoundError(tool)
    return path


def run_tool(
    cmd: List[str],
    timeout: int = 300,
    check_binary: bool = True,
) -> subprocess.CompletedProcess:
    if check_binary and cmd:
        check_tool(cmd[0])

    logger.info("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise ToolTimeoutError(f"Tool '{cmd[0]}' timed out after {timeout}s")
    except FileNotFoundError:
        raise ToolNotFoundError(cmd[0])

    if result.returncode != 0:
        logger.warning(
            "Tool '%s' exited with code %d: %s",
            cmd[0],
            result.returncode,
            result.stderr.strip(),
        )

    return result
