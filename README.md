Technical Details 
A.1 System Requirements 
To ensure smooth operation of the forensic toolkit, a basic but stable computing 
environment is required. The tool was designed to be lightweight and compatible with 
commonly available hardware, making it ideal for students, researchers, and entry-level 
investigators who may not have access to high-performance machines. The following 
outlines the recommended and minimum system requirements for installing and using 
the tool effectively. 
Hardware Requirements 
● Processor: Intel Core i3 or higher (recommended: Core i5 or above) 
● RAM: Minimum 4 GB (recommended: 8 GB for better performance) 
● Storage: At least 200 MB of free disk space for the tool and log storage 
● Display: 13" screen or larger, with at least 1366x768 resolution 
● USB Port: Required for connecting Android devices via USB cable 
Software Requirements 
● Operating System: Windows 10 or later (Tool is also portable to Linux/macOS 
with minor changes) 
● Python Version: Python 3.8 or newer 
● ADB (Android Debug Bridge): Installed and added to system path (can also 
be bundled locally) 
● Python Libraries: 
○ tkinter (for GUI) 
○ subprocess 
○ os, re, datetime, csv, json 
○ threading (for background tasks) 
All required libraries can be installed easily using pip and are included in the project 
documentation for quick setup. 
Android Device Requirements 
● Android Version: Android 7.0 (Nougat) and above 
● USB Debugging: Must be enabled from developer options 
● No Root Required: The tool works with non-rooted devices for ethical and 
legal use 
A.2 Installation Guide 
✅
 Install Python 3.8 or above and add it to system PATH 
✅
 Download and extract ADB (Android Platform Tools) 
✅
 Add ADB folder to system environment variables (PATH) 
✅
 Enable USB Debugging on the Android device via Developer Options 
✅
 Connect device to PC and allow debugging permission 
✅
 Use adb devices to confirm connection 
✅
 Install required Python libraries using pip: 
● tk 
● requests 
● pyperclip 
● pandas
