📱 Android Forensic Toolkit – README
📌 Technical Details
🔧 A.1 System Requirements
The Android Forensic Toolkit is designed to operate in a lightweight environment, ideal for students, researchers, and entry-level investigators. Below are the minimum and recommended requirements for running the toolkit efficiently.

🖥️ Hardware Requirements
Component	Minimum	Recommended
Processor	Intel Core i3	Intel Core i5 or higher
RAM	4 GB	8 GB
Storage	200 MB free space	200 MB free space
Display	13" @ 1366x768	13" or larger
USB Port	Required (for device connection)	Required

💽 Software Requirements
Operating System: Windows 10 or later

Note: Portable to Linux/macOS with minor modifications.

Python Version: Python 3.8 or newer

ADB (Android Debug Bridge):

Must be installed

Added to system environment path

(Can be bundled locally)

Required Python Libraries:

tkinter (GUI)

subprocess

os, re, datetime, csv, json

threading (for background operations)

💡 All libraries can be easily installed via pip.

📱 Android Device Requirements
Android Version: 7.0 (Nougat) and above

USB Debugging: Must be enabled via Developer Options

Root Access: ❌ Not required (designed for ethical & legal use)

⚙️ A.2 Installation Guide
Follow these steps to get started with the toolkit:

✅ Install Python 3.8+

Download Python and ensure it is added to the system PATH.

✅ Download ADB (Android Platform Tools)

Download ADB

✅ Add ADB to System PATH

Add the extracted folder path to your system environment variables.

✅ Enable USB Debugging

On your Android device, go to Settings > Developer Options > Enable USB Debugging.

✅ Connect Android Device

Use a USB cable and allow debugging permissions when prompted.

✅ Verify ADB Connection

Run: adb devices in terminal/command prompt to confirm connection.

✅ Install Required Python Libraries
Run the following in your terminal:

bash
Copy
Edit
pip install tk requests pyperclip pandas
📂 You are now ready to run the forensic toolkit and start interacting with connected Android devices in a secure and ethical manner.

