import argparse
import logging
import psutil
import shutil
import subprocess
import re
import sys

def setup_argparse():
    """
    Sets up the argument parser for the script.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Monitors PowerShell execution policy and script block logging, alerting on changes.")
    parser.add_argument("--interval", type=int, default=60, help="Interval in seconds to check for changes (default: 60)")
    parser.add_argument("--log_file", type=str, default="powershell_monitor.log", help="Path to the log file (default: powershell_monitor.log)")
    parser.add_argument("--execution_policy_check", action="store_true", help="Enable execution policy monitoring")
    parser.add_argument("--script_block_logging_check", action="store_true", help="Enable script block logging monitoring")
    parser.add_argument("--powershell_processes_check", action="store_true", help="Enable monitoring for PowerShell processes")

    return parser

def get_execution_policy():
    """
    Retrieves the current PowerShell execution policy.

    Returns:
        str: The execution policy string, or None if an error occurs.
    """
    try:
        # Get-ExecutionPolicy with no scope reports the effective
        # policy, the end result of every scope layered together. A
        # change in a scope that is being overridden higher up is
        # invisible to me, and so is a per process policy, because
        # the powershell I launch to ask starts under its own.
        result = subprocess.run(["powershell.exe", "-Command", "Get-ExecutionPolicy"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting execution policy: {e}")
        return None
    except FileNotFoundError:
        logging.error("PowerShell not found. Ensure it's in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def check_script_block_logging():
    """
    Checks if script block logging is enabled.

    Returns:
        bool: True if enabled, False otherwise, or None if an error occurs.
    """
    try:
        result = subprocess.run(["powershell.exe", "-Command", "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name EnableScriptBlockLogging | Select-Object -ExpandProperty EnableScriptBlockLogging"], capture_output=True, text=True, check=True)
        output = result.stdout.strip()

        # Check for a valid numeric value.
        if output.isdigit():
            # Reaching this line is the rare path. When the policy value
            # is not set at all, which is the ordinary state of a machine
            # without a group policy for it, the Get-ItemProperty call
            # above fails and the function returns None in the handlers
            # below, so the monitor logs a failed check every cycle and
            # never establishes a baseline for this check at all. Only a
            # machine where someone set the value gets a verdict.
            return bool(int(output))
        else:
            logging.warning(f"Unexpected output from ScriptBlockLogging registry check: {output}")
            return None

    except subprocess.CalledProcessError as e:
        logging.error(f"Error checking script block logging: {e}")
        return None
    except FileNotFoundError:
        logging.error("PowerShell not found. Ensure it's in your PATH.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def monitor_powershell_processes():
    """
    Monitors running processes for PowerShell.

    Returns:
        list: A list of PowerShell process names and PIDs.
    """
    powershell_processes = []
    for process in psutil.process_iter(['pid', 'name']):
        try:
            # The name test is a substring, and it cuts both ways: any
            # process with powershell anywhere in its name counts, while
            # pwsh, the name PowerShell 7 actually runs under, does not
            # contain it and is never reported. A modern PowerShell
            # session is invisible to this check.
            if "powershell" in process.info['name'].lower():
                powershell_processes.append((process.info['name'], process.info['pid']))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Handle cases where the process disappears or access is denied
        except Exception as e:
          logging.error(f"Error occurred while checking process: {process.info['name']}, {e}")
    return powershell_processes

def main():
    """
    Main function to execute the monitoring logic.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Validate the interval argument
    if args.interval <= 0:
        print("Error: Interval must be a positive integer.")
        sys.exit(1)

    if not (args.execution_policy_check or args.script_block_logging_check or args.powershell_processes_check):
        print("Error: No check selected. Enable at least one of --execution_policy_check, --script_block_logging_check, or --powershell_processes_check.")
        sys.exit(1)

    if shutil.which("powershell.exe") is None:
        print("Error: powershell.exe not found. This tool requires Windows with PowerShell available on the PATH.")
        sys.exit(1)

    # Configure logging to console and to the named log file
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logging.getLogger('').addHandler(file_handler)
    logging.info("Starting PowerShell activity monitor.")

    # Store initial states
    previous_execution_policy = None
    previous_script_block_logging = None
    previous_powershell_processes = set()

    while True:
        try:
            if args.execution_policy_check:
                current_execution_policy = get_execution_policy()

                if current_execution_policy is not None:
                    if previous_execution_policy is None:
                        previous_execution_policy = current_execution_policy # Initialize
                    elif current_execution_policy != previous_execution_policy:
                        logging.warning(f"Execution policy changed from {previous_execution_policy} to {current_execution_policy}")
                        print(f"Execution policy changed from {previous_execution_policy} to {current_execution_policy}")
                        previous_execution_policy = current_execution_policy # Update
                else:
                    logging.error("Failed to get execution policy. Skipping check.")

            if args.script_block_logging_check:
                current_script_block_logging = check_script_block_logging()

                if current_script_block_logging is not None:
                    if previous_script_block_logging is None:
                        previous_script_block_logging = current_script_block_logging  # Initialize

                    elif current_script_block_logging != previous_script_block_logging:
                        logging.warning(f"Script block logging changed from {previous_script_block_logging} to {current_script_block_logging}")
                        print(f"Script block logging changed from {previous_script_block_logging} to {current_script_block_logging}")
                        previous_script_block_logging = current_script_block_logging  # Update
                else:
                    logging.error("Failed to check script block logging. Skipping check.")

            if args.powershell_processes_check:
              current_powershell_processes = set(monitor_powershell_processes())
              # Unlike the two policy checks above, which take their first
              # reading silently as a baseline, this check starts from an
              # empty set, so every PowerShell process already running when
              # I start is announced as newly started. The identity is name
              # plus pid, so a pid reused between polls also reads as one
              # process stopping and another starting.
              for name, pid in sorted(current_powershell_processes - previous_powershell_processes):
                logging.info(f"PowerShell process started: {name} (PID {pid})")
                print(f"PowerShell process started: {name} (PID {pid})")
              for name, pid in sorted(previous_powershell_processes - current_powershell_processes):
                logging.info(f"PowerShell process stopped: {name} (PID {pid})")
                print(f"PowerShell process stopped: {name} (PID {pid})")
              previous_powershell_processes = current_powershell_processes

            # The import lives inside the loop, re-executed on every
            # cycle. It costs almost nothing, and it marks where this
            # file grew by accretion rather than by design.
            import time
            time.sleep(args.interval)

        except KeyboardInterrupt:
            logging.info("Exiting PowerShell activity monitor.")
            break
        except Exception as e:
            logging.error(f"An unhandled error occurred: {e}")
            break

if __name__ == "__main__":
    main()