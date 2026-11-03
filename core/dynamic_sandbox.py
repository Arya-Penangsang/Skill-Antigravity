import os
import time
import subprocess
import psutil
import winreg

class DynamicSandbox:
    def __init__(self, target_path, timeout_seconds=10):
        self.target_path = target_path
        self.timeout = timeout_seconds

    def _snapshot_registry_run(self):
        snapshot = {}
        keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]
        for root, subkey in keys:
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as k:
                    count = winreg.QueryInfoKey(k)[1]
                    for i in range(count):
                        name, val, _ = winreg.EnumValue(k, i)
                        snapshot[f"{subkey}\\{name}"] = val
            except Exception:
                pass
        return snapshot

    def _snapshot_temp_dir(self):
        temp_dir = os.environ.get("TEMP", "")
        if not os.path.exists(temp_dir):
            return set()
        try:
            return set(os.listdir(temp_dir))
        except Exception:
            return set()

    def run_dynamic_analysis(self, dry_run=False):
        if dry_run:
            return {
                "execution_status": "Dry-run Mode (Skipped execution)",
                "spawned_processes": [],
                "network_activity": [],
                "dropped_files": [],
                "registry_modifications": []
            }

        initial_reg = self._snapshot_registry_run()
        initial_temp = self._snapshot_temp_dir()

        spawned_procs = []
        network_events = []

        proc = None
        try:
            # Launch binary under controlled subprocess
            proc = subprocess.Popen(
                [self.target_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            pid = proc.pid
            spawned_procs.append({
                "pid": pid,
                "name": os.path.basename(self.target_path),
                "parent_pid": os.getpid()
            })

            # Monitor loop during execution window
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                if proc.poll() is not None:
                    break

                try:
                    p = psutil.Process(pid)
                    # Check child processes
                    children = p.children(recursive=True)
                    for child in children:
                        c_info = {
                            "pid": child.pid,
                            "name": child.name(),
                            "cmdline": " ".join(child.cmdline()) if child.cmdline() else ""
                        }
                        if c_info not in spawned_procs:
                            spawned_procs.append(c_info)

                    # Check open connections
                    conns = p.connections(kind='inet')
                    for c in conns:
                        conn_info = {
                            "fd": c.fd,
                            "family": str(c.family),
                            "type": str(c.type),
                            "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                            "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                            "status": c.status
                        }
                        if conn_info not in network_events:
                            network_events.append(conn_info)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                time.sleep(0.5)

        except Exception as e:
            return {
                "execution_status": f"Execution Failed: {str(e)}",
                "spawned_processes": [],
                "network_activity": [],
                "dropped_files": [],
                "registry_modifications": []
            }
        finally:
            # Terminate target process after timeout
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass

        # Compare post-execution artifacts
        post_reg = self._snapshot_registry_run()
        post_temp = self._snapshot_temp_dir()

        reg_diff = []
        for k, v in post_reg.items():
            if k not in initial_reg:
                reg_diff.append({"action": "Added", "key": k, "value": v})
            elif initial_reg[k] != v:
                reg_diff.append({"action": "Modified", "key": k, "old_value": initial_reg[k], "new_value": v})

        temp_diff = list(post_temp - initial_temp)

        return {
            "execution_status": "Completed (Isolated execution window)",
            "execution_time_seconds": self.timeout,
            "spawned_processes": spawned_procs,
            "network_activity": network_events,
            "dropped_files": temp_diff,
            "registry_modifications": reg_diff
        }
