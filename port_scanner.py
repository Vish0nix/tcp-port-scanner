from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import queue
import socket
import threading
import tkinter as tk
from tkinter import ttk


def scan_port(target_ip, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((target_ip, port)) == 0


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"


def scan_target(target_ip, start_port, end_port, on_result=None, stop_event=None, max_workers=100):
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError("Ports must satisfy 1 <= start_port <= end_port <= 65535.")
    if not 1 <= max_workers <= 500:
        raise ValueError("max_workers must be between 1 and 500.")

    open_ports = []
    ports = iter(range(start_port, end_port + 1))
    pending = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        def submit_available():
            while len(pending) < max_workers * 2:
                if stop_event is not None and stop_event.is_set():
                    return
                try:
                    port = next(ports)
                except StopIteration:
                    return
                pending[executor.submit(scan_port, target_ip, port)] = port

        submit_available()
        while pending:
            completed, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in completed:
                port = pending.pop(future)
                is_open = future.result()
                service = get_service_name(port) if is_open else ""
                if is_open:
                    open_ports.append(port)

                if on_result is not None:
                    on_result(port, is_open, service)

            submit_available()

    return open_ports


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP Port Scanner")
        self.root.minsize(560, 440)

        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.scanned_count = 0

        self.target_var = tk.StringVar(value="127.0.0.1")
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1024")
        self.workers_var = tk.StringVar(value="100")
        self.status_var = tk.StringVar(value="Ready. Scan only systems you are authorized to test.")

        self._build_interface()
        self.root.after(100, self._process_events)

    def _build_interface(self):
        container = ttk.Frame(self.root, padding=20)
        container.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        container.columnconfigure(1, weight=1)

        ttk.Label(container, text="TCP Port Scanner", font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w"
        )
        ttk.Label(
            container,
            text="Service names are standard port mappings, not protocol fingerprinting.",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 16))

        ttk.Label(container, text="Target host or IPv4").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=4)
        ttk.Entry(container, textvariable=self.target_var).grid(row=2, column=1, columnspan=2, sticky="ew", pady=4)

        port_fields = ttk.Frame(container)
        port_fields.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(4, 12))
        ttk.Label(port_fields, text="Start port").grid(row=0, column=0, sticky="w")
        ttk.Entry(port_fields, textvariable=self.start_port_var, width=10).grid(
            row=1, column=0, sticky="w", padx=(0, 12), pady=(4, 0)
        )
        ttk.Label(port_fields, text="End port").grid(row=0, column=1, sticky="w")
        ttk.Entry(port_fields, textvariable=self.end_port_var, width=10).grid(
            row=1, column=1, sticky="w", padx=(0, 12), pady=(4, 0)
        )
        ttk.Label(port_fields, text="Threads").grid(row=0, column=2, sticky="w")
        ttk.Entry(port_fields, textvariable=self.workers_var, width=8).grid(
            row=1, column=2, sticky="w", padx=(0, 12), pady=(4, 0)
        )

        actions = ttk.Frame(port_fields)
        actions.grid(row=1, column=3, sticky="e", pady=(4, 0))
        port_fields.columnconfigure(3, weight=1)
        self.scan_button = ttk.Button(actions, text="Start scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=(0, 8))
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_button.grid(row=0, column=1)

        self.progress = ttk.Progressbar(container, mode="determinate")
        self.progress.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 12))

        results_frame = ttk.Frame(container)
        results_frame.grid(row=5, column=0, columnspan=3, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        container.rowconfigure(5, weight=1)

        self.results = ttk.Treeview(
            results_frame,
            columns=("port", "service", "state"),
            show="headings",
            height=8,
        )
        self.results.heading("port", text="Port")
        self.results.heading("service", text="Service")
        self.results.heading("state", text="State")
        self.results.column("port", width=100, anchor="center")
        self.results.column("service", width=180, anchor="center")
        self.results.column("state", width=120, anchor="center")
        self.results.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.results.configure(yscrollcommand=scrollbar.set)

        ttk.Label(container, textvariable=self.status_var).grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(12, 0)
        )
        self.root.bind("<Return>", lambda _event: self.start_scan())

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            self.status_var.set("Enter a target host or IPv4 address.")
            return

        try:
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
            max_workers = int(self.workers_var.get())
        except ValueError:
            self.status_var.set("Ports and thread count must be whole numbers.")
            return

        if not 1 <= start_port <= end_port <= 65535:
            self.status_var.set("Choose a range where 1 <= start port <= end port <= 65535.")
            return
        if not 1 <= max_workers <= 500:
            self.status_var.set("Choose between 1 and 500 threads.")
            return

        for item in self.results.get_children():
            self.results.delete(item)

        self.scanned_count = 0
        self.progress.configure(maximum=end_port - start_port + 1, value=0)
        self.stop_event.clear()
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set(f"Scanning {target}...")

        worker = threading.Thread(
            target=self._run_scan,
            args=(target, start_port, end_port, max_workers),
            daemon=True,
        )
        worker.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping after the current connection check...")
        self.stop_button.configure(state="disabled")

    def _run_scan(self, target, start_port, end_port, max_workers):
        try:
            open_ports = scan_target(
                target,
                start_port,
                end_port,
                on_result=lambda port, is_open, service: self.events.put(
                    ("result", port, is_open, service)
                ),
                stop_event=self.stop_event,
                max_workers=max_workers,
            )
            self.events.put(("finished", open_ports, self.stop_event.is_set()))
        except OSError as error:
            self.events.put(("error", str(error)))

    def _process_events(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break

            if event[0] == "result":
                _, port, is_open, service = event
                self.scanned_count += 1
                self.progress.configure(value=self.scanned_count)
                if is_open:
                    self.results.insert("", "end", values=(port, service, "Open"))
                self.status_var.set(f"Scanned {self.scanned_count} ports; {len(self.results.get_children())} open.")
            elif event[0] == "finished":
                _, open_ports, was_stopped = event
                self._set_idle()
                if was_stopped:
                    self.status_var.set(f"Scan stopped. Found {len(open_ports)} open ports.")
                else:
                    self.status_var.set(f"Scan complete. Found {len(open_ports)} open ports.")
            elif event[0] == "error":
                self._set_idle()
                self.status_var.set(f"Scan failed: {event[1]}")

        self.root.after(100, self._process_events)

    def _set_idle(self):
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")


def main():
    root = tk.Tk()
    PortScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
