# **Runbook: Hunt for malicious inbox rules**

## **Objective**

To provide a standardized procedure for proactively hunting for and investigating suspicious inbox rule creation. This includes enriching the source IP of the rule creation, pivoting to identify all other activities from that IP, and generating a comprehensive report with tactical and strategic recommendations.

## **Scope**

- **In Scope:** Querying for rule events, analyzing rule properties, enriching the source IP and any external domains, investigating all related IP activities, documenting findings, and generating a formal, structured report.
- **Out of Scope:** Full incident response for the compromised account. This runbook's findings are a critical input into the main `compromised_user_account_response.md` IRP.

## **Inputs**

- `${USER_ID}` (Mandatory): The user ID to investigate.
- `${CASE_ID}` (Mandatory): The SOAR case ID for documentation.
- _`(Optional)`_ `${START_DATETIME}`: The specific date and time to start searching backward from.
- _(Optional)_` ${TIME_FRAME_HOURS}`: Lookback period in hours (default: 72).

## **Outputs**

- `${SUSPICIOUS_RULES_FOUND}`: A structured list of suspicious inbox rules.
- `${SOURCE_IP_ENRICHMENT}`: A summary of the reputation and SIEM context for the source IP address.
- `${RELATED_IP_ACTIVITIES}`: A summary of other anomalous activities from the same source IP.
- `${ANALYSIS_SUMMARY}`: A text summary of all findings.
- `${DOCUMENTATION_STATUS}`: The status of documentation in the SOAR case.
- `${REPORT_FILE_PATH}`: The local file path to the generated Markdown report.

## **Tools**

- `secops-mcp`:`search_security_events`,`lookup_entity`
- `gti-mcp`:`get_domain_report`,`get_ip_address_report`
- `secops-soar`:`post_case_comment`
- `write_report`
- `get_current_time`

## **Workflow Steps & Diagram**

1. **Receive Inputs:** Obtain all necessary inputs.
2. **Execute SIEM Search for Rules:** Find inbox rule creation events for the`${USER_ID}` using `secops-mcp.search_security_events`.
3. **Analyze Rule Properties:** Analyze each rule for malicious characteristics (forwarding, keywords, actions, naming).
4. **Enrich External Domains:** If a rule forwards to an external domain, enrich it using `gti-mcp.get_domain_report` and `secops-mcp.lookup_entity`.
5. **Enrich Source IP and Investigate Related Activity:**
    - **Condition:** If a suspicious rule creation event is identified, extract the `${SOURCE_IP}` and `${RULE_CREATION_TIME}` from the event log.
    - **Enrich IP:** The analyst will first enrich the `${SOURCE_IP}` to understand its nature:
        - Use `gti-mcp.get_ip_address_report` to check for known malicious reputation, geographic location, and hosting details.
        - Use `secops-mcp.lookup_entity` to get a summary of the IP's historical activity within the environment.
        - Store findings in `${SOURCE_IP_ENRICHMENT}`.
    - **Investigate Other Activities:** The analyst performs a new SIEM search using `secops-mcp.search_security_events` to find _all_ activity from that `${SOURCE_IP}` in a time window around the rule creation (e.g., +/- 1 hour from `${RULE_CREATION_TIME}`).
    - **Analysis:** The analyst reviews the results, correlating the IP's reputation with all observed actions to identify other potentially malicious activities (e.g., logins to other accounts, file downloads, password changes).
    - **Output:** Findings are summarized in `${RELATED_IP_ACTIVITIES}`.
6. **Synthesize and Document in SOAR:**
    - The analyst consolidates all findings: `${SUSPICIOUS_RULES_FOUND}`, `${SOURCE_IP_ENRICHMENT}`, and `${RELATED_IP_ACTIVITIES}`.
    - A comprehensive `${ANALYSIS_SUMMARY}` is posted to the `${CASE_ID}` using `secops-soar.post_case_comment`.
7. **Generate Markdown Report:** A formal report is compiled containing all synthesized findings. The report structure must include:
    1. Executive summary: A brief, high-level overview of the incident, key findings, and the primary recommendation. 
    2. Technical analysis:
        2.1. Event analysis: Detailed breakdown of the malicious rule creation event(s).
        2.2. Indicator of Compromise (IoC) analysis: Detailed enrichment and context for the source IP and any other identified IoCs.
   3. MITRE ATT&CK mapping: Based on `${ANALYSIS_SUMMARY}`, provide a list of TTPs in order to give more context to the reader.
   4. Potential attack scenarios: Based on `${ANALYSIS_SUMMARY}`, suggest one or more attack scenarios that could be on going.
   5. Recommendations:
       5.1. Tactical recommendations: Specific, actionable steps for the incident response team (e.g., disable account, block IP, delete rule).
       5.2. Strategic recommendations: Suggestions for enhancing security and resiliency posture (e.g., improve detection rules, policy changes, user training).
8. **Recommend Next Steps:**
    - Based on the full scope of activity, the analyst recommends the next action. If malicious activity is confirmed, the recommendation **must be** to escalate to the full `compromised_user_account_response.md` IRP.

---

### **SIEM Query for Inbox Rule Creation**

- **Creation or modification of Inbox Rules around `${TIME_FRAME_HOURS}` hours of `${EVENT_DATETIME}`**

```
( principal.user.email_addresses = "${USER_ID}" OR target.user.email_addresses = "${USER_ID}" OR network.email.from = "${USER_ID}" OR network.email.to = "${USER_ID}" )
AND ( metadata.product_event_type = "New-InboxRule" or metadata.product_event_type = "Set-InboxRule" )
AND ( security_result.rule_labels.key = "ForwardTo" nocase or security_result.rule_labels.key = "ForwardAsAttachmentTo" nocase or security_result.rule_labels.key = "RedirectTo" nocase or security_result.rule_labels.key = "MoveToFolder" nocase )
```

---

### **Workflow Diagram**

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant SOAR as secops-soar

    Analyst->>AutomatedAgent: Start Inbox Rule Hunt\nInput: USER_ID, CASE_ID, START_DATETIME (opt), TIME_FRAME

    %% Step 2
    AutomatedAgent->>SIEM: search_security_events(text="Custom Query for USER_ID", ...)
    SIEM-->>AutomatedAgent: Rule Creation Events

    %% Step 3 & 4
    note over AutomatedAgent: Analyze events for suspicious characteristics
    opt Suspicious External Domain Found
        AutomatedAgent->>GTI: get_domain_report(domain="external.com")
        GTI-->>AutomatedAgent: Domain Reputation
        AutomatedAgent->>SIEM: lookup_entity(entity_value="external.com")
        SIEM-->>AutomatedAgent: SIEM History for Domain
    end

    %% Step 5
    opt Suspicious Rule Event Found
        note over AutomatedAgent: Extract Source IP and Timestamp
        AutomatedAgent->>GTI: get_ip_address_report(ip_address="Source IP")
        GTI-->>AutomatedAgent: IP Reputation (Source IP Enrichment)
        AutomatedAgent->>SIEM: lookup_entity(entity_value="Source IP")
        SIEM-->>AutomatedAgent: SIEM History for IP (Source IP Enrichment)
        AutomatedAgent->>SIEM: search_security_events(text="Activity from Source IP", start_time=..., end_time=...)
        SIEM-->>AutomatedAgent: Related IP Activities
        note over AutomatedAgent: Analyze for other malicious actions
    end

    %% Step 6
    note over AutomatedAgent: Prepare summary including IP Enrichment, IP Activities, and recommendations
    AutomatedAgent->>SOAR: post_case_comment(case_id=CASE_ID, comment="Inbox Rule Hunt Summary...")
    SOAR-->>AutomatedAgent: Comment Confirmation (DOCUMENTATION_STATUS)

    %% Step 7
    note over AutomatedAgent: Compile all findings into Markdown report content
    AutomatedAgent->>AutomatedAgent: get_current_time()
    AutomatedAgent->>AutomatedAgent: write_report(report_name=..., report_contents=...)
    note left of AutomatedAgent: Report file created (REPORT_FILE_PATH)

    %% Step 8
    AutomatedAgent->>Analyst: attempt_completion(result="Inbox rule hunt complete. Findings documented in CASE_ID. Report generated at REPORT_FILE_PATH.")
```   

## **Completion Criteria**

- The SIEM has been searched for inbox rule events related to the `${USER_ID}`.
- All discovered rules have been analyzed for suspicious characteristics.
- Any external domains have been enriched using GTI and SIEM lookups.
- All IPs have been enriched using GTI and SIEM lookups.
- A summary of the findings has been documented as a comment in the specified `${CASE_ID}`.
- A formal Markdown report summarizing the investigation has been created and saved locally.
- A clear recommendation for the next steps has been provided.
