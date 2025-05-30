# Network Map

Network Map is a simple GTK application that uses `nmap` to scan your network and display the results. You can specify a target (hostname, IP address, or CIDR block), choose some common nmap options, and view the scan output.

## Features

*   Scan specified targets using nmap.
*   Option for OS fingerprinting (`-O`).
*   Option to add custom nmap arguments.
*   Displays a list of found hosts.
*   Shows detailed nmap output for the selected host.
*   **Scan Profiles:** Save and manage frequently used scan configurations.
    *   Create, edit, and delete scan profiles.
    *   Import and export profiles in JSON format, allowing you to share configurations.
*   **Enhanced Results Display:** Color-coded port states (open, closed, filtered) in the detailed host view for better readability. Single host scan results are automatically expanded.
*   **Customizable Appearance:** Choose between light, dark, or system theme, and select a custom font for scan results.
*   **Configurable DNS Servers:** Specify custom DNS servers for Nmap scans.
*   **Default Nmap Arguments:** Set default arguments that apply to all scans.

## Usage

1.  **Enter Target:** In the "Target/CIDR" field, type the hostname, IP address, or network range (e.g., scanme.nmap.org, 192.168.1.1, 10.0.0.0/24, or multiple targets like target1.example.com,target2.example.com 192.168.2.0/24) you want to scan. You can specify multiple targets by separating them with commas or spaces.
2.  **Set Options (Optional):**
    *   Toggle the "OS Fingerprinting" switch if you want to attempt OS detection (often requires root/administrator privileges).
    *   Enter any additional valid `nmap` arguments (e.g., `-p 1-1000`, `-sU`) in the "additional arguments" field. The UI also provides direct controls for Stealth Scan (-sS), No Ping (-Pn), Port Specification (-p), Timing Templates (-T0 to -T5), and selecting common NSE Scripts.
    *   Select or create a **Scan Profile** to quickly apply a set of pre-configured options.
3.  **Start Scan:** Click the "Start Scan" button (or press Enter in the Target field).
4.  **View Results:**
    *   The application will show a spinner and "Scanning..." status while `nmap` is working.
    *   Once complete, a list of discovered hosts will appear on the left.
    *   Click on a host from the list to see its detailed scan output in the text view on the right.
    *   If no hosts are found, or if there's an error, an appropriate message will be displayed.

## Building and Running

This project uses the Meson build system.

### Dependencies

*   Python 3 (usually `python3`)
*   Python `python-nmap` module (e.g., `pip install python-nmap` or `python3-nmap` from system packages if available). This is handled by the Flatpak build if using Flatpak.
*   Python GObject Introspection libraries: (Typically `python3-gi`, `python3-gi-cairo`. Covered by GTK4 dependencies below).
*   GTK4 and LibAdwaita libraries and their development files.
    *   On Debian/Ubuntu: `sudo apt install libgtk-4-dev libadwaita-1-dev gir1.2-gtk-4.0 gir1.2-adw-1 python3-gi python3-gi-cairo gir1.2-pango-1.0`
    *   On Fedora: `sudo dnf install gtk4-devel libadwaita-devel gobject-introspection-devel python3-gobject cairo-gobject-devel pango-devel`
*   `nmap` executable (must be in your system's PATH or at a standard location like `/usr/bin/nmap` or `/usr/local/bin/nmap`). The application will try to find it.
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
    (The executable is typically `builddir/src/networkmap`)

*   **Install and run (after compiling):**
    ```bash
    sudo ninja -C builddir install
    ```
    (Or `sudo meson install -C builddir`).
    After installation, the application should be available in your system's application menu (as `Network Map`) or runnable from the command line:
    ```bash
    com.github.mclellac.NetworkMap
    ```

### Flatpak

A Flatpak manifest (`com.github.mclellac.NetworkMap.json`) is provided for building and distributing the application as a Flatpak.

**Build and Install Flatpak:**

1.  **Install `flatpak` and `flatpak-builder`:**
    *   On Debian/Ubuntu: `sudo apt install flatpak flatpak-builder`
    *   On Fedora: `sudo dnf install flatpak flatpak-builder`
    *   Ensure Flathub remote is added: `flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo`

2.  **Install GNOME SDK (if not already installed):**
    ```bash
    flatpak install org.gnome.Sdk//48 
    flatpak install org.gnome.Platform//48
    ```
    (Replace `48` with the version specified in the manifest if it changes).

3.  **Build and install the application:**
    Navigate to the root directory of this repository (where `com.github.mclellac.NetworkMap.json` is located).
    ```bash
    flatpak-builder --user --install --force-clean build-dir com.github.mclellac.NetworkMap.json
    ```

4.  **Run the Flatpak application:**
    ```bash
    flatpak run com.github.mclellac.NetworkMap
    ```

## Preferences

The application settings can be accessed via the primary menu (top-right corner of the window) -> Preferences.
You can configure:
*   **Theme:** System, Light, or Dark.
*   **Results Font:** Font family and size for the scan results text view.
*   **DNS Servers:** Comma-separated list of DNS servers for Nmap to use.
*   **Default Nmap Arguments:** Arguments to be included with every Nmap scan by default.
*   **Scan Profiles:** Manage your saved scan configurations (see "Scan Profiles" under Features).

## Troubleshooting

*   **Freezing:** If the application freezes, ensure `nmap` is working correctly on your system and that the target is responsive or correctly handled by `nmap`'s timeouts.
*   **Permissions:** OS Fingerprinting (`-O`) and some other advanced `nmap` options may require root/administrator privileges to run correctly. If scans fail or hang with these options, the application will attempt to request privileges (e.g., via `pkexec` or macOS administrator prompt). Ensure these mechanisms are available and configured on your system if you intend to use these features. For Flatpak, privilege escalation for Nmap works via `flatpak-spawn --host pkexec`.
*   **Nmap Not Found:** If the application reports that Nmap is not found, ensure `nmap` is installed and accessible either via your system's `PATH` or in a standard location (e.g., `/usr/bin/nmap`, `/usr/local/bin/nmap`). For Flatpak, Nmap is bundled.
*   **Flatpak Build Issues:** If `flatpak-builder` fails, check that you have the correct GNOME SDK version installed and that Flathub is configured. Environment issues with `flatpak-builder` caching can sometimes occur; try building on a clean system or VM if persistent cache errors occur.
```
