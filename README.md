# LYADI
A.K.A **L**et **Y**our **A**I **D**o **I**t

An MCP (Model Context Protocol) Server specifically designed to help with reverse engineering tasks, majorly focused on Android side.


https://github.com/user-attachments/assets/69379b8a-8be0-41de-8839-80c2eeb9931d


## Features

- **APK Decompilation**: Easily decompile APK files using APKEditor.
- **Radare2 Integration**: Utilize Radare2 for advanced binary analysis.
- **ADB/Logcat Integration**: Use ADB and Logcat for real-time debugging.
- **Custom Scripts**: Run custom scripts for specific reverse engineering tasks.
- **Automation**: Automate repetitive tasks to save time and effort.
- **Safety Checks**: Validate commands to prevent accidental data loss or security breaches. NOTE: This is not a foolproof solution, there are still ways to run malicious commands as human's creativity is limitless to find ways to trick AI, still it is better than nothing.

<img src="images/safety.png" alt="Safety Check" width="500"/>
... and more!

## Installation

1. Clone the repository:
```shell
git clone https://github.com/AbhiTheModder/LYADI.git
```

2. Navigate to the project directory:
```shell
cd LYADI
```

3. Install dependencies:
```shell
./setup.sh
```

## Usage

Instead of default `stdio` transport, this server uses `sse` transport, making it compatible with almost all MCP clients and reducing the need of installing anything extra (like `uv`, `npm`, etc.).

1. Start the server:

```shell
python src/main.py
```

You'll see an output like this:
```shell
INFO:     Started server process [32084]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     127.0.0.1:51657 - "GET /sse HTTP/1.1" 200 OK
```

If so then you're good to go!

The server is now running on `http://0.0.0.0:8000/sse`, you can use it with any MCP client.

Some examples are given below:

2. Connect to the server using your preferred MCP client.

- Continue Dev (`~/.continue/config.json`):
```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "LYADI",
        "transport":{
          "type": "sse",
          "url": "http://0.0.0.0:8000/sse"
        }
      }
    ]
  }
}
```

- Cursor (`~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "LYADI": {
      "url": "http://0.0.0.0:8000/sse"
    }
  }
}
```

- VSCode (`./vscode/mcp.json`):
```json
{
  "servers": {
    "LYADI": {
      "type": "sse",
      "url": "http://0.0.0.0:8000/sse"
    }
  }
}
```

- Claude Desktop (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "LYADI": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://0.0.0.0:8000/sse"
      ]
    }
  }
}
```

- WindSurf (`~/.codeium/windsurf/mcp_config.json`):
```json
{
  "mcpServers": {
    "LYADI": {
      "serverUrl": "http://0.0.0.0:8000/sse"
    }
  }
}
```

- Cline (`cline_mcp_settings.json`):
```json
{
  "mcpServers": {
    "LYADI": {
      "url": "http://0.0.0.0:8000/sse",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments
- [MCP Python](https://github.com/modelcontextprotocol/python-sdk)
- [APKiD](https://github.com/rednaga/APKiD)
- [Androguard](https://github.com/androguard/androguard)
- [YARA](https://github.com/VirusTotal/yara) | [YARA-Python](https://github.com/VirusTotal/yara-python) | [YARA-Python-Dex](https://github.com/MobSF/yara-python-dex)
- [APKEditor](https://github.com/REAndroid/APKEditor)
- [ADB](https://developer.android.com/tools/adb)