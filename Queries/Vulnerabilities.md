# Finding Vulnerabilities in XDR and Microsoft Stack

## For Devices Enrolled in MDE with access to MDVM 👇

```
// Search for a specific CVE in MDE enrolled devices (replace 'CVE-XXXX-XXXX' with the actual CVE ID)
union DeviceTvmSoftwareVulnerabilities, DeviceEvents, DeviceFileEvents
| where CveId == 'CVE-2024-21339'
| project DeviceName, LocalIP, Timestamp
```


