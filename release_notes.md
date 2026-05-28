# 🛡️ Sentinella EDR v1.2.2 (Open-Source Release)

We are excited to share the initial open-source release of **Sentinella**, a real-time kernel-level endpoint detection and response (EDR) platform for Linux systems. 

> [!NOTE]
> This is the official **open-source version**. We are planning further operations and updates in the near future (including File Integrity Monitoring, container context mapping, and SIEM cloud export). Stay tuned!

---

## 📦 What's Included (Release Assets)
* **`Sentinella_1.2.2_amd64.AppImage`**: A portable package. Recommended for quick execution.
* **`sentinella_1.2.2_amd64.deb`**: Debian installation package. Automatically sets up menus, icons, and shortcuts.

---

## 🚀 How to Run the Release Binary

Since Sentinella attaches eBPF filters directly to kernel tracepoints, it **must be run with root/superland privileges** (`sudo`).

### Option A: Running the AppImage (easiest)
1. Download the `.AppImage` file from the assets below.
2. Open your terminal, navigate to your downloads, and make it executable:
   ```bash
   chmod +x Sentinella_1.2.2_amd64.AppImage
   ```
3. Run the AppImage with system privileges:
   ```bash
   sudo ./Sentinella_1.2.2_amd64.AppImage
   ```

### Option B: Installing the Debian Package (`.deb`)
1. Download the `.deb` file from the assets below.
2. Install it using the package manager in your terminal:
   ```bash
   sudo dpkg -i sentinella_1.2.2_amd64.deb
   ```
   *(If there are missing dependency errors, resolve them with `sudo apt-get install -f`)*.
3. Once installed, run it with sudo from your terminal:
   ```bash
   sudo sentinella
   ```
   *(Or launch it from your desktop applications menu, entering your root password when prompted)*.
