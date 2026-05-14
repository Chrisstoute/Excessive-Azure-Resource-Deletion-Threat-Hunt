<div align="center">

# Excessive Azure Resource Deletion Threat Hunt

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:000000,50:7F0000,100:DC143C&height=170&section=header&text=Microsoft%20Sentinel%20Threat%20Hunt&fontSize=34&fontColor=ffffff&animation=fadeIn" />

<br>

<img src="./assets/v-for-vendetta-theme.jpg" alt="V for Vendetta inspired threat hunt theme" width="500"/>

<br><br>

**Platform:** Microsoft Sentinel  
**Focus:** Detection of excessive Azure resource deletion activity

<div align="center">

<table>
<tr>
<td align="center">

<h3>🛡️ Cyber Range Scenario Credit 🛡️</h3>

<strong>This threat hunt scenario was provided by Josh Madakor, CEO of The Cyber Range.</strong>

<br><br>

<a href="https://www.skool.com/cyber-range">
  <img src="https://img.shields.io/badge/JOIN%20THE%20CYBER%20RANGE-CLICK%20HERE-red?style=for-the-badge&labelColor=000000&color=ff0000" alt="Join The Cyber Range">
</a>

</td>
</tr>
</table>

</div>

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


I started by confirming that the `AzureActivity` table contained recent log data. This gave me confidence that Sentinel had the required Azure control-plane activity available for hunting.

![1_Confirming_AzureActivity_Data_Exists](Screenshots/1_Confirming_AzureActivity_Data_Exists.jpg)

---

### 2. Review raw write/delete Azure activity events

Next, I searched for Azure activity where the operation ended in `WRITE` or `DELETE`. This helped narrow the dataset down to resource creation, modification, and deletion activity.

![2_Raw_Write_Delete_AzureActivity_Events](Screenshots/2_Raw_Write_Delete_AzureActivity_Events.jpg)

---

### 3. Identify successful write/delete events

I then filtered the results to focus only on successful or succeeded activity. This removed failed attempts and allowed me to focus on actions that actually affected Azure resources.

![3_Successful_Write_Delete_Events](Screenshots/3_Successful_Write_Delete_Events.jpg)

---

### 4. Summarize write/delete activity by caller

After confirming successful activity, I summarized the events by caller and source IP address. This helped identify which account or identity was responsible for the highest volume of resource changes.

![4_Summarizing_Write_Delete_Activity_By_Caller](Screenshots/4_Summarizing_Write_Delete_Activity_By_Caller.jpg)

---

### 5. Break down operations by type

I broke the activity down by operation type to understand what actions were being performed. This helped separate normal administrative activity from potentially destructive activity, such as resource deletion.

![5_Breakdown_By_Operation_Type](Screenshots/5_Breakdown_By_Operation_Type.jpg)

---

### 6. Drill into top suspicious caller

Once I identified a high-volume caller, I filtered the results down to that specific caller. This allowed me to investigate the account’s activity more closely instead of reviewing all Azure activity at once.

![6_Drilling_Into_Top_Suspicious_Caller](Screenshots/6_Drilling_Into_Top_Suspicious_Caller.jpg)

---

### 7. Review suspicious caller operation breakdown

I summarized the suspicious caller’s actions by operation name. This showed that the caller was performing a large number of delete operations related to network interfaces and public IP addresses.

![7_Suspicious_Caller_Operation_Breakdown](Screenshots/7_Suspicious_Caller_Operation_Breakdown.jpg)

---

### 8. Review detailed delete events for suspicious caller

I reviewed the detailed delete events to validate the suspicious activity. This step confirmed the caller, caller IP address, operation names, timestamps, resource groups, and activity status values.

![8_Detailed_Delete_Events_For_Suspicious_Caller](Screenshots/8_Detailed_Delete_Events_For_Suspicious_Caller.jpg)

---

### 9. Identify affected resource groups by delete activity

I grouped the delete activity by resource group to understand the scope of impact. This helped identify which Azure resource groups were affected most heavily by the deletion activity.

![9_Affected_Resource_Groups_By_Delete_Activity](Screenshots/9_Affected_Resource_Groups_By_Delete_Activity.jpg)

---

### 10. Build Sentinel detection query

After validating the suspicious pattern, I built a detection query that looks for excessive successful delete activity involving network interfaces and public IP addresses. This query became the foundation for the Sentinel analytics rule.

![10_Sentinel_Detection_Query_For_Excessive_Delete_Activity](Screenshots/10_Sentinel_Detection_Query_For_Excessive_Delete_Activity.jpg)

---

### 11. Configure analytics rule details

I created a Microsoft Sentinel scheduled analytics rule and gave it a clear name, description, severity, and MITRE ATT&CK mapping. The rule was mapped to Impact because the activity involved potential destructive cloud resource deletion.

![11_Analytics_Rule_Details](Screenshots/11_Analytics_Rule_Details.jpg)

---

### 12. Configure set rule logic and entity mapping

In the rule logic section, I added the finalized KQL query and configured entity mapping. I mapped the caller as an account entity and the caller IP address as an IP entity so Sentinel could enrich the incident with useful investigation context.

![12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_1](Screenshots/12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_1.jpg)

I also configured the query schedule, lookup period, alert threshold, and event grouping. The rule was set to generate an alert when the query returned results, grouping matching events into a single alert.

![12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_2](Screenshots/12_Set_Rule_Logic_Query_And_Entity_Mapping_pt_2.jpg)

---

### 13. Configure incident settings and alert grouping

I configured the rule to create incidents in Microsoft Sentinel and enabled alert grouping. This helps reduce noise by grouping related alerts into a single incident for investigation.

![13_Incident_Settings_Alert_Grouping](Screenshots/13_Incident_Settings_Alert_Grouping.jpg)

---

### 14. Review and create analytics rule

Before saving the rule, I reviewed the configuration to verify the query, entity mappings, scheduling, severity, and incident settings were correct.

![14_Review_And_Create_Analytics_Rule](Screenshots/14_Review_And_Create_Analytics_Rule.jpg)

---

### 15. Confirm analytics rule is created and enabled

After creating the analytics rule, I confirmed that it appeared in the Sentinel analytics rule list and was enabled. This verified that Sentinel would begin running the detection on schedule.

![15_Analytics_Rule_Created_And_Enabled](Screenshots/15_Analytics_Rule_Created_And_Enabled.jpg)

---

### 16. Confirm Sentinel incident triggered from analytics rule

Once the rule ran, I confirmed that a Sentinel incident was generated from the analytics rule. This validated that the detection logic worked and successfully produced an alert.

![16_Sentinel_Incident_Triggered_From_Analytics_Rule](Screenshots/16_Sentinel_Incident_Triggered_From_Analytics_Rule.jpg)

---

### 17. Assign incident and open investigate action

I assigned the incident to myself and changed the status to active to begin the investigation workflow. I then opened the investigation action to review the incident relationships.

![17_Assigned_Incident_And_Opened_Investigate_Action](Screenshots/17_Assigned_Incident_And_Opened_Investigate_Action.jpg)

---

### 18. Review Sentinel incident investigation graph

I reviewed the Sentinel investigation graph to visualize the relationship between the incident, caller accounts, and IP entities. This helped show how Sentinel connects evidence and entities during an investigation.

![18_Sentinel_Incident_Investigation_Graph](Screenshots/18_Sentinel_Incident_Investigation_Graph.jpg)

---

### 19. Document incident activity log actions

I documented containment, eradication, and recovery notes in the incident activity log. This created an investigation record showing the response actions taken during the incident.

![19_Incident_Activity_Log_Containment_Eradication_Recovery](Screenshots/19_Incident_Activity_Log_Containment_Eradication_Recovery.jpg)

---

### 20. Close incident as true positive

Finally, I closed the incident as a true positive because the analytics rule correctly detected excessive Azure resource deletion activity. This completed the Sentinel incident lifecycle from detection to closure.

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
