A KQL query to search for a file with a specific SHA256 hash across:
Azure storage, Azure VMs, user endpoints, emails, OneDrive, and Teams.

What each table does:
DeviceFileEvents: This table contains information about file creation, modification, and other events from user endpoints.
It's primarily used to hunt across user endpoints.

EmailAttachmentInfo: This table contains information about files that were attached to emails.
It's used to hunt across email services.

AlertEvidence: This table contains evidence associated with Defender XDR alerts, which can come from various sources including
Azure services, user endpoints, emails, OneDrive, and Teams.


```
let hash = "SHA256_HASH_VALUE";
union
(
    DeviceFileEvents
    | where SHA256 == hash
    | project Timestamp, DeviceId, DeviceName, FileName, FolderPath, SHA256, FileSize, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountUpn, InitiatingProcessCommandLine, TableName = "DeviceFileEvents"
),
(
    EmailAttachmentInfo
    | where SHA256 == hash
    | project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256, FileSize, TableName = "EmailAttachmentInfo"
),
(
    AlertEvidence
    | where SHA256 == hash
    | project Timestamp, AlertId, Title, Categories, AttackTechniques, ServiceSource, DetectionSource, EntityType, EvidenceRole, FileName, SHA256, Severity, TableName = "AlertEvidence"
)
```
