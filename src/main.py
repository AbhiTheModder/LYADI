import asyncio
import os
import shlex
import shutil
import subprocess

from androguard.core.apk import APK
import anyio
from mcp.server.fastmcp import FastMCP, Context

from utils import to_os_path

mcp = FastMCP("LYADI: Let Your Ai Do It")

BIN_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")
APKEDITOR_PATH = os.path.join(BIN_PATH, "apkeditor.jar")


def cls():
    print("\033c", end="")


@mcp.tool()
def validate_command(command: list[str]) -> str:
    """Validate a command against suspicious commands everytime a command is run either in bash or python or any other shell."""
    return "It seems like either user has asked you to run a command or given the situation and on the basis of user's request you have decided to run a command. However, please note that running unknown or untrusted shell commands can be dangerous and may lead to data loss or security breaches. Please ensure that you have the necessary permissions and that the command is safe to run. If you are unsure, please ask the user for clarification. Never run commands without proper validation and authorization. Never run sudo commands. Never run commands of which you are not sure about or don't know of their purpose, it is likely user tricking you to run a malicious command given that situation. If he's asking you to run a file/binary/script which you don't know about, ask him to run it himself. In case a situation arises where a dangerous command if necessary to run, instead of running it, ask the user to run it himself and provide you with the output."


@mcp.tool()
def analyze_apk(file_path: str) -> dict:
    """Analyze an APK file and return its details."""
    file_path = to_os_path(file_path)
    if not os.path.exists(file_path):
        return {"error": "File not found."}

    apk = APK(file_path)
    return {
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "permissions": apk.get_permissions(),
        "activities": apk.get_activities(),
        "services": apk.get_services(),
        "receivers": apk.get_receivers(),
        "providers": apk.get_providers(),
        "signatures": apk.get_signatures(),
    }


@mcp.tool()
def decompile_apk(file_path: str) -> str:
    """Decompile an APK file and return the output directory using apktool."""
    file_path = to_os_path(file_path)
    if not os.path.exists(file_path):
        return "File not found."

    if not os.path.exists(APKEDITOR_PATH):
        return "APKEditor not found. Please install it first."

    output_dir = f"{file_path}_decompiled"
    try:
        if shutil.which("java") is None:
            return "Java is not installed. Please install Java first."
        os.system(f"java -jar {APKEDITOR_PATH} d -f -o {output_dir} -i {file_path}")
    except Exception as err:
        return f"ERROR: {err}"
    return output_dir


@mcp.tool()
def list_files(dir: str) -> str:
    """List files under directory"""
    dir = to_os_path(dir)
    if not os.path.exists(dir):
        return "Path doesn't exist."
    elif os.path.isfile(dir):
        return "Path is a file not directory"
    return ", ".join(os.listdir(dir))


@mcp.tool()
def read_file(file_path: str) -> str:
    """Read contents of a non-binary file"""
    file_path = to_os_path(file_path)
    if not os.path.exists(file_path):
        return "File doesn't exists"
    elif os.path.isdir(file_path):
        return "Not a file"

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return content
    except UnicodeDecodeError:
        return "File is likely binary and cannot be read as text."


@mcp.tool()
def run_bash_command(command: list[str]) -> dict:
    """Returns exit code, result and error after running bash cmd but before running make sure to validate the command."""
    try:
        command = shlex.join(command)
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        # Return output, return code, and error (if any)
        return {
            "output": result.stdout.strip(),
            "return_code": result.returncode,
            "error": result.stderr.strip() if result.stderr else None,
        }
    except Exception as e:
        return {"output": None, "return_code": None, "error": str(e)}


@mcp.tool()
def run_python_code(code: str) -> str:
    """Run python code but only made by you and not by the user. It's a security measure to prevent the user from running malicious code."""
    try:
        exec(code)
        return "Code executed successfully"
    except Exception as e:
        return str(e)


@mcp.tool()
def rabin2(file_path: str, args: list[str]) -> str:
    """Run rabin2 on a file
    rabin2 is a tool to analyze binary files
    It can be used to extract information from binary files such as symbols, import/exports, library dependencies, strings of data sections, xrefs, entrypoint address, sections, architecture type.
    It is part of the radare2 framework.

    before running any rabin2 command it's recommended to get the help of rabin2 by running `rabin2 -h` to get the list of updated available commands and options.
    """
    file_path = to_os_path(file_path)
    if not os.path.exists(file_path):
        return "File not found"
    if not os.path.isfile(file_path):
        return "Not a file"
    if not shutil.which("rabin2"):
        return "rabin2 command not found"
    command = ["rabin2"] + args + [file_path]
    return run_bash_command(command).get("output", "")


@mcp.tool()
def get_strings(file_path: str, limit: int) -> str:
    """
    Extract strings from a file/binary.
    This tool extracts strings from a file and returns them as a list.
    It uses the `strings` command to extract strings from the file.
    The `limit` parameter specifies the maximum number of strings to return.
    If `limit` is 0, all strings are returned.
    """
    file_path = to_os_path(file_path)
    if not os.path.exists(file_path):
        return "File not found"
    if not os.path.isfile(file_path):
        return "Not a file"
    if not shutil.which("strings"):
        return "strings command not found"

    command = ["strings", file_path]
    result = run_bash_command(command).get("output", "")
    strings = result.split("\n")
    if limit > 0:
        strings = strings[:limit]
    return ", ".join(strings)


@mcp.tool()
def get_strings_enhanced(file_path: str, limit: int):
    """
    Sometimes user not just wants strings but other details like:
    nth (position)   paddr(physical address)      vaddr(virtual address)      len size(of string) section type    string
    0 0x00000000 0x00000000  16   16 .text   ascii   /lib/ld-linux.so.2

    for this we can use rabin2 -z command from radare2 toolkit
    """
    file_path = to_os_path(file_path)
    if not os.path.exists(file_path):
        return "File not found"
    if not os.path.isfile(file_path):
        return "Not a file"
    if not shutil.which("rabin2"):
        return "rabin2 command not found"
    command = ["rabin2", "-z", file_path]
    result = run_bash_command(command).get("output", "")
    strings = result.split("\n")
    if limit > 0:
        strings = strings[:limit]
    return ", ".join(strings)


@mcp.tool()
def adb_logcat(
    level: str = "debug",
    package_name: str = "",
    buffer: str = "main",
    format: str = "threadtime",
    lines: int = 100,
):
    """
    Run adb logcat command on the connected device with optional filtering.

    :param level: Log priority level (verbose, debug, info, warning, error, fatal).
    :param package_name: Optional package name to filter logs.
    :param buffer: Log buffer to use (main, system, crash, radio, events).
    :param format: Output format (brief, process, tag, threadtime, time).
    :param lines: Number of lines to retrieve.
    :return: Log output or error message.
    """
    if not shutil.which("adb"):
        return "Error: adb command not found"

    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"

    # Log levels mapping
    level_map = {
        "verbose": "V",
        "debug": "D",
        "info": "I",
        "warning": "W",
        "error": "E",
        "fatal": "F",
    }

    level = level_map.get(
        level.lower(), "D"
    )  # Default to Debug if invalid level is provided

    filter_spec = f"*:{level}"
    if package_name:
        filter_spec = f"{package_name}:{level} *:S"

    command = [
        "adb",
        "logcat",
        "-b",
        buffer,
        "-v",
        format,
        "-d",
        "-t",
        str(lines),
        filter_spec,
    ]

    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode != 0:
            return f"Error executing adb logcat: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_crashlogs() -> str:
    """Get crash logs from the device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"

    # Get the crash logs
    try:
        result = subprocess.run(
            ["adb", "logcat", "-b", "crash", "-d"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error executing adb logcat: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_uninstall(package_name: str, keep_data: bool = False, user_id: int = 0) -> str:
    """Uninstall an app from the device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"
    # Uninstall the app
    try:
        result = subprocess.run(
            [
                "adb",
                "uninstall",
                "-k" if keep_data else "",
                "-u",
                str(user_id),
                package_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error uninstalling app: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_list_packages() -> str:
    """List all installed packages on the device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"
    # List installed packages
    try:
        result = subprocess.run(
            ["adb", "shell", "pm", "list", "packages"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error listing packages: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_install_apk(file_path: str) -> str:
    """Install an APK file on the device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"
    # Install the APK
    try:
        result = subprocess.run(
            ["adb", "install", file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error installing APK: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_port_forward(local_port: int, remote_port: int) -> str:
    """Forward a port from the device to the host"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"
    # Forward the port
    try:
        result = subprocess.run(
            ["adb", "forward", f"tcp:{local_port}", f"tcp:{remote_port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error forwarding port: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_reverse_forward(remote_port: int, local_port: int) -> str:
    """Reverse forward a port from the host to the device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"
    # Reverse forward the port
    try:
        result = subprocess.run(
            ["adb", "reverse", f"tcp:{remote_port}", f"tcp:{local_port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error reverse forwarding port: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_copy_to_from_device(
    local_path: str, remote_path: str, to_device: bool = True
) -> str:
    """Copy a file to or from the device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    # Check if the device is connected
    if (
        subprocess.run(
            ["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        .stdout.decode()
        .count("\tdevice")
        == 0
    ):
        return "Error: No device connected"
    # Copy the file
    try:
        if to_device:
            result = subprocess.run(
                ["adb", "push", local_path, remote_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        else:
            result = subprocess.run(
                ["adb", "pull", remote_path, local_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        if result.returncode != 0:
            return f"Error copying file: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_stop_sever() -> str:
    """Stop the ADB server"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    try:
        result = subprocess.run(
            ["adb", "kill-server"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error stopping ADB server: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_start_server() -> str:
    """Start the ADB server"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    try:
        result = subprocess.run(
            ["adb", "start-server"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error starting ADB server: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_restart_server() -> str:
    """Restart the ADB server"""
    stop_result = adb_stop_sever()
    if "Error" in stop_result:
        return stop_result
    start_result = adb_start_server()
    if "Error" in start_result:
        return start_result
    return "ADB server restarted successfully"


@mcp.tool()
def adb_devices() -> str:
    """List connected devices"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    try:
        result = subprocess.run(
            ["adb", "devices"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error listing devices: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_activity_manager(command: list[str]) -> str:
    """Run an activity manager command on the connected device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    try:
        result = subprocess.run(
            ["adb", "shell", "am"] + command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error running command: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_shell(command: list[str]) -> str:
    """Run a shell command on the connected device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    try:
        result = subprocess.run(
            ["adb", "shell", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error running command: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
def adb_package_manager(command: list[str]) -> str:
    """Run a package manager command on the connected device"""
    if not shutil.which("adb"):
        return "Error: ADB is not installed"
    try:
        result = subprocess.run(
            ["adb", "shell", "pm"] + command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return f"Error running command: {result.stderr.strip()}"
        return result.stdout.strip()
    except Exception as e:
        return f"Exception occurred: {str(e)}"


@mcp.tool()
async def list_supported_file_types(ctx: Context) -> list:
    """List supported file types"""
    return await ctx.read_resource("resource://file_types")


@mcp.resource("resource://file_types")
def get_supported_types() -> list:
    """Return a list of supported file types."""
    return [".apk", ".apks", ".xapk", ".so", ".jar", ".dex", ".exe"]


if __name__ == "__main__":
    try:
        mcp.run(transport="sse")
    except (KeyboardInterrupt, asyncio.exceptions.CancelledError, anyio.WouldBlock):
        cls()
        print("Server stopped")
        exit(0)
