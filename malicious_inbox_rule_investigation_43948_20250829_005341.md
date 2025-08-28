
# Malicious Inbox Rule Investigation Report

**Case ID:** 43948

## 1. Executive Summary

On June 27, 2025, a new inbox rule was created in the mailbox of `mario.rossi@acme.example`. The rule was created from a known malicious IP address (`81.235.15.164`) located in Sweden. The rule is designed to intercept emails from `giulia.bianchi@example.example`, move them to the "Archivio" folder, and mark them as read. This activity is indicative of a compromised user account and is likely a preparatory step for a Business Email Compromise (BEC) or other malicious activity. Immediate action is required to contain the threat and investigate the extent of the compromise.

## 2. Technical Analysis

### 2.1. Event Analysis

*   **Log Type:** Exchange Audit Log
*   **Operation:** `New-InboxRule`
*   **User:** `mario.rossi@acme.example`
*   **Source IP:** `81.235.15.164`
*   **Timestamp:** `2025-06-27T15:35:47`
*   **Rule Details:**
    *   **Name:** "IT"
    *   **From:** `giulia.bianchi@example.example`
    *   **Action 1:** Move email to "Archivio" folder.
    *   **Action 2:** Mark email as read.
    *   **Action 3:** Stop processing further rules.

### 2.2. Indicator of Compromise (IoC) Analysis

*   **IP Address:** `81.235.15.164`
    *   **ISP:** Telia Network Services
    *   **Location:** Angelholm, Sweden
    *   **Reputation:** Bad, known source of malicious activities.

## 3. MITRE ATT&CK Mapping

*   **T1564.008: Hide Artifacts: Email Hiding Rules:** The attacker created an inbox rule to move emails from a specific sender to a less conspicuous folder and mark them as read. This is a classic technique to hide phishing or BEC follow-up emails from the legitimate user.
*   **T1078: Valid Accounts:** The attacker is using a compromised account to create the rule.

## 4. Potential Attack Scenarios

1.  **Business Email Compromise (BEC):** The attacker has compromised `mario.rossi@acme.example` and is setting up a rule to intercept emails from `giulia.bianchi@example.example`. This could be part of a larger scheme to impersonate Mario and send fraudulent requests to Giulia, while hiding her replies from Mario.
2.  **Information Theft:** The attacker is interested in the correspondence between Mario and Giulia and is using the rule to exfiltrate information without Mario's knowledge.

## 5. Recommendations

### 5.1. Tactical Recommendations

*   **Immediate:**
    *   Disable the user account `mario.rossi@acme.example`.
    *   Block the IP address `81.235.15.164` at the firewall/VPN.
    *   Delete the malicious inbox rule.
*   **Follow-up:**
    *   Investigate the user's recent activities for any other suspicious behavior.
    *   Notify the user and the security team.

### 5.2. Strategic Recommendations

*   Implement MFA for all users to prevent unauthorized access.
*   Improve detection rules for suspicious inbox rule creation from known malicious IPs.
*   Provide user training on identifying and reporting suspicious activities.
