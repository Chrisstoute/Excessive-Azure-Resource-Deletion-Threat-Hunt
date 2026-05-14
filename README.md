<div align="center">

# Excessive Azure Resource Deletion Threat Hunt

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0B0B0B,100:C1121F&height=180&section=header&text=Microsoft%20Sentinel%20Threat%20Hunt&fontSize=34&fontColor=FFFFFF&animation=fadeIn" />

<br>

<img src="assets/v-for-vendetta-theme.jpg" alt="V for Vendetta themed image" width="260"/>

<br><br>

> **Theme:** *V for Vendetta-inspired visual style*  
> **Platform:** Microsoft Sentinel  
> **Focus:** Detection of excessive Azure resource deletion activity

</div>

---

## Overview

This project documents a Microsoft Sentinel threat hunting and incident response lab focused on detecting excessive Azure resource deletion activity.

The investigation used AzureActivity logs, KQL, Microsoft Sentinel analytics rules, entity mapping, incident creation, investigation graphing, and incident closure workflows.

---

## Scenario

A suspicious caller was observed performing excessive **DELETE** operations against Azure resources, specifically involving:

- Network interfaces
- Public IP addresses

The objective of this hunt was to identify:

- who initiated the deletions,
- what resources were affected,
- how frequently the activity occurred,
- and whether it warranted a Sentinel analytics rule and incident response workflow.

---

## Tools Used

- Microsoft Sentinel
- AzureActivity Logs
- KQL (Kusto Query Language)
- Sentinel Analytics Rules
- Incident Investigation Graph
- MITRE ATT&CK Framework
- GitHub

---

## MITRE ATT&CK Mapping

- **T1485** – Data Destruction

---

## Investigation Workflow

### 1. Confirm AzureActivity data exists
![1_Confirming_AzureActivity_Data_Exists](Screenshots/1_Confirming_AzureActivity_Data_Exists.jpg)

### 2. Review raw write/delete Azure activity events
![2_Raw_Write_Delete_AzureActivity_Events](Screenshots/2_Raw_Write_Delete_AzureActivity_Events.jpg)

### 3. Identify successful write/delete events
![3_Successful_Write_Delete_Events](Screenshots/3_Successful_Write_Delete_Events.jpg)

### 4. Summarize write/delete activity by caller
![4_Summarizing_Write_Delete_Activity_By_Caller](Screenshots/4_Summarizing_Write_Delete_Activity_By_Caller.jpg)

### 5. Break down operations by type
![5_Breakdown_By_Operation_Type](Screenshots/5_Breakdown_By_Operation_Type.jpg)

### 6. Drill into top suspicious caller
![6_Drilling_Into_Top_Suspicious_Caller](Screenshots/6_Drilling_Into_Top_Suspicious_Caller.jpg)

### 7. Review suspicious caller operation breakdown
![7_Suspicious_Caller_Operation_Breakdown](Screenshots/7_Suspicious_Caller_Operation_Breakdown.jpg)

### 8. Review detailed delete events for suspicious caller
![8_Detailed_Delete_Events_For_Suspicious_Caller](Screenshots/8_Detailed_Delete_Events_For_Suspicious_Caller.jpg)

### 9. Identify affected resource groups by delete activity
![9_Affected_Resource_Groups_By_Delete_Activity](Screenshots/9_Affected_Resource_Groups_By_Delete_Activity.jpg)

### 10. Build Sentinel detection query
![10_Sentinel_Detection_Query_For_Excessive_Delete_Activity](Screenshots/10_Sentinel_Detection_Query_For_Excessive_Delete_Activity.jpg)

### 11. Configure analytics rule details
![11_Analytics_Rule_Details](Screenshots/11_Analytics_Rule_Details.jpg)

### 12. Configure set rule logic and entity mapping
![12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_1](Screenshots/12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_1.jpg)

![12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_2](Screenshots/12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_2.jpg)

### 13. Configure incident settings and alert grouping
![13_Incident_Settings_Alert_Grouping](Screenshots/13_Incident_Settings_Alert_Grouping.jpg)

### 14. Review and create analytics rule
![14_Review_And_Create_Analytics_Rule](Screenshots/14_Review_And_Create_Analytics_Rule.jpg)

### 15. Confirm analytics rule is created and enabled
![15_Analytics_Rule_Created_And_Enabled](Screenshots/15_Analytics_Rule_Created_And_Enabled.jpg)

### 16. Confirm Sentinel incident triggered from analytics rule
![16_Sentinel_Incident_Triggered_From_Analytics_Rule](Screenshots/16_Sentinel_Incident_Triggered_From_Analytics_Rule.jpg)

### 17. Assign incident and open investigate action
![17_Assigned_Incident_And_Opened_Investigate_Action](Screenshots/17_Assigned_Incident_And_Opened_Investigate_Action.jpg)

### 18. Review Sentinel incident investigation graph
![18_Sentinel_Incident_Investigation_Graph](Screenshots/18_Sentinel_Incident_Investigation_Graph.jpg)

### 19. Document incident activity log actions
![19_Incident_Activity_Log_Containment_Eradication_Recovery](Screenshots/19_Incident_Activity_Log_Containment_Eradication_Recovery.jpg)

### 20. Close incident as true positive
![20_Closing_Incident_As_True_Positive](Screenshots/20_Closing_Incident_As_True_Positive.jpg)

---

## Key Findings

- AzureActivity logs showed repeated successful **DELETE** operations.
- The most suspicious caller performed a high volume of deletions across multiple resource groups.
- The primary deleted resource types involved:
  - **Microsoft.Network/networkInterfaces/delete**
  - **Microsoft.Network/publicIPAddresses/delete**
- A custom **Microsoft Sentinel analytics rule** was created to detect this behavior.
- The rule successfully triggered an incident.
- The incident was assigned, investigated, documented, and closed as a **True Positive**.

---

## Response Actions

### Containment
- Investigated the caller and associated IP addresses.
- Escalated suspicious deletion activity for review.
- Created a Sentinel analytics rule to detect repeated delete behavior.

### Eradication
- Documented the malicious/suspicious pattern.
- Identified affected resource groups and repeated delete operations.
- Used detection logic to improve future visibility.

### Recovery
- Triggered and validated the Sentinel alert workflow.
- Confirmed that the detection rule properly generated an incident.
- Closed the incident after documenting findings and response actions.

### Post-Incident Activities
- Preserved screenshots and query results for documentation.
- Added the investigation as a GitHub portfolio project.
- Improved detection capability for future excessive deletion behavior.

---

## Detection Query

```kql
AzureActivity
| where OperationNameValue in (
    "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE",
    "MICROSOFT.NETWORK/PUBLICIPADDRESSES/DELETE"
)
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    DeleteCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DeletedOperations = make_set(OperationNameValue, 10),
    ResourceGroups = make_set(ResourceGroup, 10),
    ResourceProviders = make_set(ResourceProvider, 10)
    by Caller, CallerIPAddress
| where DeleteCount >= 10
| order by DeleteCount desc
