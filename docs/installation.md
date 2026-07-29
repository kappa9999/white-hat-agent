# Installation and updates

White Hat Agent Core installs as an isolated command-line tool. It does not need a cloned repository, a preinstalled
Python runtime, administrator privileges, or changes to an existing Python environment.

## Supported shells

| Environment | Bootstrap | Continuously tested |
|---|---|---|
| macOS | POSIX `install.sh` | GitHub-hosted macOS runner |
| Linux | POSIX `install.sh` | GitHub-hosted Ubuntu runner |
| Windows Subsystem for Linux | POSIX `install.sh` | Same Linux path, plus local WSL smoke testing |
| Windows 10/11 | PowerShell `install.ps1` | GitHub-hosted Windows runner and Windows PowerShell 5.1 |

Python 3.12 is the default managed runtime. Set `WHA_PYTHON` if a compatible newer interpreter is required.

## Install or update

Re-running the matching command performs an update as well as an installation.

### macOS, Linux, or WSL

```bash
curl -LsSf https://raw.githubusercontent.com/kappa9999/white-hat-agent/main/install.sh | sh
```

### Windows PowerShell

```powershell
irm https://raw.githubusercontent.com/kappa9999/white-hat-agent/main/install.ps1 | iex
```

The bootstrap performs four explicit operations:

1. locate `uv`, or use Astral's official standalone installer when it is missing;
2. request an isolated Python 3.12 tool environment from `uv`;
3. install or refresh `white-hat-agent` from the repository's GitHub archive; and
4. ask `uv` to add its tool executable directory to the user shell profile.

Open a new terminal if `wha` is not immediately on `PATH`. The installer always prints the exact installed executable
path. You can also inspect it directly:

```bash
uv tool dir --bin
```

## Review before execution

Piping a remote script to a shell is convenient, but it is still remote code execution. Inspect the script first when
that is appropriate for your environment:

### POSIX

```bash
curl -LsSf https://raw.githubusercontent.com/kappa9999/white-hat-agent/main/install.sh | less
curl -LsSf https://raw.githubusercontent.com/kappa9999/white-hat-agent/main/install.sh -o install.sh
sh install.sh
```

### PowerShell

```powershell
irm https://raw.githubusercontent.com/kappa9999/white-hat-agent/main/install.ps1 | more
irm https://raw.githubusercontent.com/kappa9999/white-hat-agent/main/install.ps1 -OutFile install.ps1
& .\install.ps1
```

## Manual installation with an existing `uv`

The equivalent package operation is:

```bash
uv tool install --reinstall --refresh --python 3.12 \
  "white-hat-agent @ https://github.com/kappa9999/white-hat-agent/archive/refs/heads/main.zip"
uv tool update-shell
```

The GitHub archive avoids requiring Git on an end user's machine. The tool environment remains isolated from system
Python and project virtual environments.

## Pinning or mirroring

The foundation-alpha installer follows `main`. For a reproducible deployment, set `WHA_SOURCE_URL` to an audited tag
or commit archive. Other bootstrap settings are also explicit environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `WHA_SOURCE_URL` | GitHub `main` archive | Exact source archive installed by `uv` |
| `WHA_PYTHON` | `3.12` | Managed Python version for the tool environment |
| `WHA_UV_BIN` | auto-detected | Existing `uv` executable or command name |
| `WHA_UV_INSTALLER_URL` | official Astral installer | Approved internal mirror or pinned bootstrap URL |
| `WHA_PACKAGE` | generated direct requirement | Advanced local, wheel, or mirror-backed package source |
| `WHA_SKIP_PATH_UPDATE` | `0` | Set to `1` to leave shell profiles unchanged |

Example pinned POSIX installation:

```bash
WHA_SOURCE_URL="https://github.com/kappa9999/white-hat-agent/archive/<commit>.zip" \
  sh install.sh
```

The same variables can be assigned through `$env:` in PowerShell.

## Initialize a workspace

Installation and project data are intentionally separate. Create as many workspaces as needed:

```bash
wha init white-hat-workspace
cd white-hat-workspace
wha doctor
```

Set `WHA_WORKSPACE` when an agent or MCP client should use one workspace without repeating `--workspace`.

## Uninstall

Remove the isolated application environment:

```bash
uv tool uninstall white-hat-agent
```

Workspaces are ordinary user-owned directories and are never deleted by the uninstaller.

## Develop from source

Contributors should use the locked development environment instead of the global tool installation:

```bash
git clone https://github.com/kappa9999/white-hat-agent.git
cd white-hat-agent
uv sync --locked --extra dev
uv run wha init .
uv run wha doctor --workspace .
```
