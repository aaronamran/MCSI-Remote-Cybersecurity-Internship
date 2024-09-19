# Write A PS Script To Turn On Hyper-V
Hyper-V, Microsoft's hypervisor, enables multiple operating systems to run on one physical machine. It enhances cybersecurity by protecting against memory-based credential theft (e.g., `lsass.exe`) and can block tools like Mimikatz, adding an extra layer of defense.

## Tasks
- Write a PowerShell script to check if Hyper-V is enabled by querying the appropriate Windows feature
- Display a message indicating whether Hyper-V is enabled or disabled
- Use PowerShell commands to enable Hyper-V on the local machine
- Display a success message after enabling Hyper-V
- Provide an option in the script to force a reboot
