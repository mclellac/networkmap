# Network Map

Network Map is a simple GTK application that uses `nmap` to scan your network and display the results. You can specify a target (hostname, IP address, or CIDR block), choose some common nmap options, and view the scan output.

## Features

*   Scan specified targets using nmap.
*   Option for OS fingerprinting (`-O`).
*   Option to add custom nmap arguments.
*   Displays a list of found hosts.
*   Shows detailed nmap output for the selected host.

## Usage

1.  **Enter Target:** In the "Target/CIDR" field, type the hostname, IP address, or network range (e.g., `localhost`, `192.168.1.1`, `10.0.0.0/24`) you want to scan.
2.  **Set Options (Optional):**
    *   Toggle the "OS Fingerprinting" switch if you want to attempt OS detection (often requires root/administrator privileges).
    *   Enter any additional valid `nmap` arguments (e.g., `-p 1-1000`, `-sU`) in the "additional arguments" field.
3.  **Start Scan:** Click the "Apply" button next to the Target field (or press Enter in the Target field).
4.  **View Results:**
    *   The application will show a spinner and "Scanning..." status while `nmap` is working.
    *   Once complete, a list of discovered hosts will appear on the left.
    *   Click on a host from the list to see its detailed scan output in the text view on the right.
    *   If no hosts are found, or if there's an error, an appropriate message will be displayed.

## Building and Running

This project uses the Meson build system.

### Dependencies

*   Python 3 (usually `python3`)
*   GTK4 and LibAdwaita libraries and their development files.
    *   On Debian/Ubuntu: `sudo apt install libgtk-4-dev libadwaita-1-dev gir1.2-gtk-4.0 gir1.2-adw-1`
    *   On Fedora: `sudo dnf install gtk4-devel libadwaita-devel gobject-introspection-devel`
*   `nmap` executable (must be in your system's PATH).
*   Python `python-nmap` module: `pip install python-nmap`
*   Meson (`meson`) and Ninja (`ninja` or `ninja-build`).
    *   `pip install meson ninja` or use your system's package manager.

### Build Steps

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Set up the build directory using Meson:**
    ```bash
    meson setup builddir
    ```
    If you need to specify a different prefix for installation (default is often `/usr/local`), you can add `--prefix=/your/desired/prefix` to this command. For local testing without installation, the default prefix is fine.

3.  **Compile the application:**
    ```bash
    ninja -C builddir
    ```
    (Some systems might use `meson compile -C builddir` instead of `ninja -C builddir`)


### Running

*   **Run from the build directory (without installation):**
    ```bash
    ./builddir/src/networkmap 
    ```
    (The executable might be directly in `builddir/networkmap` or `builddir/src/com.github.mclellac.NetworkMap` depending on meson setup - check `meson.build` for `executable()` name if unsure. The current `src/meson.build` suggests `networkmap` which is then renamed by `meson.install_script` for the actual installation, but for running from build dir, it's likely `builddir/src/networkmap`)

    Alternatively, you might be able to run:
    ```bash
    python3 src/main.py
    ```
    from the root of the repository if all dependencies are met and paths resolve correctly, but using the meson-built executable is preferred.

*   **Install and run (after compiling):**
    ```bash
    sudo ninja -C builddir install
    ```
    (Or `sudo meson install -C builddir`).
    After installation, the application should be available in your system's application menu (as `com.github.mclellac.NetworkMap`) or runnable from the command line using its application ID if the `.desktop` file is correctly installed and your prefix is standard:
    ```bash
    com.github.mclellac.NetworkMap
    ```
    Or just:
    ```bash
    networkmap
    ```
    (Depending on how it's installed and if the install path is in your `PATH`).


## Troubleshooting

*   **Freezing:** If the application freezes, ensure `nmap` is working correctly on your system and that the target is responsive or correctly handled by `nmap`'s timeouts.
*   **`RuntimeError: Data access methods are unsupported...`:** This was a bug in previous versions. Ensure you have the latest version where this is fixed.
*   **Permissions:** OS Fingerprinting (`-O`) and some other advanced `nmap` options may require root/administrator privileges to run correctly. If scans fail or hang with these options, try running the application (or `nmap` itself) with elevated privileges.
```
