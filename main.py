import argparse
import logging
import psutil
import subprocess
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

    # Configure logging to file
    logging.basicConfig(filename=args.log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("Starting PowerShell activity monitor.")

    # Store initial states
    previous_execution_policy = None
    previous_script_block_logging = None

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
              powershell_processes = monitor_powershell_processes()
              if powershell_processes:
                logging.info(f"Active PowerShell processes: {powershell_processes}")
                print(f"Active PowerShell processes: {powershell_processes}")

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