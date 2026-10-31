![Banner](banner.png)

# monitor-powershellactivity
Monitors PowerShell execution policy and script block logging, alerting on changes that could indicate malicious activity or configuration changes. - Focused on System monitoring and alerts

This tool requires Windows with PowerShell available as powershell.exe on the PATH. If powershell.exe is not found, the run exits 1 at startup with a plain error line. At least one check flag must be given; a run with no check flag exits 1 at startup, naming the flags.

What the tool records is limited to three signals: the execution policy string, the EnableScriptBlockLogging boolean, and the names and PIDs of running powershell processes, reported when a process starts or stops. No PowerShell command content, command lines, or script text is captured.

## Install
`git clone https://github.com/ShadowStrikeHQ/monitor-powershellactivity`

## Usage
`python main.py [params]`

Output goes to the console and to the log file named by --log_file.

## Parameters
- `-h`: Show help message and exit
- `--interval`: Interval in seconds to check for changes (default: 60)
- `--log_file`: Path to the log file (default: powershell_monitor.log)
- `--execution_policy_check`: Enable execution policy monitoring
- `--script_block_logging_check`: Enable script block logging monitoring
- `--powershell_processes_check`: Enable monitoring for PowerShell processes

## License
Copyright (c) ShadowStrikeHQ
