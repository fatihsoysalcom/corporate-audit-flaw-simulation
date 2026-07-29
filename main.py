import datetime

class LogEntry:
    """Represents a single action logged in the system."""
    def __init__(self, user_id: str, action_type: str, details: str = ""):
        self.timestamp = datetime.datetime.now()
        self.user_id = user_id
        self.action_type = action_type
        self.details = details

    def __str__(self):
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] User '{self.user_id}': {self.action_type} - {self.details}"

class SystemLogger:
    """Collects and stores all system actions."""
    def __init__(self):
        self.logs: list[LogEntry] = []

    def record_action(self, user_id: str, action_type: str, details: str = ""):
        entry = LogEntry(user_id, action_type, details)
        self.logs.append(entry)
        print(f"Logged: {entry}")

class InternalAudit:
    """Performs an audit on system logs based on defined rules."""
    def __init__(self, system_logger: SystemLogger):
        self.logger = system_logger
        # Keywords that indicate potentially suspicious activity
        self.suspicious_keywords = ["stalk", "unauthorized_access", "data_export_sensitive"]
        # Users whose actions might be subject to different (e.g., less stringent) scrutiny
        # in a system with governance weaknesses.
        self.privileged_users = ["admin_auditor", "ceo_assistant"]

    def perform_audit(self) -> list[str]:
        """Audits logs and returns a list of findings."""
        print("\n--- Performing Internal Audit ---")
        findings = []
        for entry in self.logger.logs:
            is_suspicious = False
            for keyword in self.suspicious_keywords:
                if keyword in entry.action_type.lower() or keyword in entry.details.lower():
                    is_suspicious = True
                    break

            if is_suspicious:
                # Initial audit logic: flags all suspicious activities,
                # but notes if performed by a privileged user.
                if entry.user_id in self.privileged_users:
                    findings.append(f"WARNING: Privileged user '{entry.user_id}' performed potentially suspicious action: {entry}")
                else:
                    findings.append(f"CRITICAL: Suspicious activity detected: {entry}")

        if findings:
            print("\nAudit Findings:")
            for f in findings:
                print(f)
        else:
            print("No suspicious activities detected.")
        print("--- Audit Complete ---")
        return findings

# --- Main simulation ---
if __name__ == "__main__":
    system_logger = SystemLogger()
    audit_department = InternalAudit(system_logger)

    print("--- Scenario 1: Normal Operations ---")
    system_logger.record_action("user123", "view_product", "Product ID: 456")
    system_logger.record_action("user456", "add_to_cart", "Product ID: 123, Qty: 1")
    audit_department.perform_audit() # Expected: No suspicious activities

    print("\n--- Scenario 2: Unethical Action Detected by Standard Audit ---")
    system_logger.record_action("user789", "stalk_user_profile", "Target: user123")
    audit_department.perform_audit() # Expected: "stalk" action flagged as CRITICAL

    print("\n--- Scenario 3: Unethical Action by Privileged User (Initial Audit) ---")
    # This action by a privileged user is initially flagged as a WARNING.
    system_logger.record_action("ceo_assistant", "unauthorized_access", "Employee records of user123")
    audit_department.perform_audit() # Expected: "unauthorized_access" flagged as WARNING

    print("\n--- Scenario 4: Demonstrating Governance/Audit Failure ---")
    # To simulate the core issue from the article (audit/governance failure),
    # we introduce a *flawed* audit mechanism that intentionally ignores
    # suspicious actions performed by privileged users.
    class FlawedInternalAudit(InternalAudit):
        def perform_audit(self) -> list[str]:
            """
            A flawed audit that fails to report suspicious activities by privileged users.
            This simulates a corporate governance weakness where certain individuals
            are not subject to proper scrutiny, leading to undetected unethical behavior.
            """
            print("\n--- Performing *FLAWED* Internal Audit (Simulating Governance Failure) ---")
            findings = []
            for entry in self.logger.logs:
                is_suspicious = False
                for keyword in self.suspicious_keywords:
                    if keyword in entry.action_type.lower() or keyword in entry.details.lower():
                        is_suspicious = True
                        break

                if is_suspicious:
                    # --- GOVERNANCE/AUDIT FLAW DEMONSTRATED HERE ---
                    # If a privileged user performs a suspicious action,
                    # the flawed audit system *intentionally ignores* it.
                    if entry.user_id in self.privileged_users:
                        print(f"INFO: Privileged user '{entry.user_id}' action '{entry.action_type}' noted but *ignored* by flawed audit policy.")
                        continue # This is the critical flaw: bypasses reporting for privileged users.
                    else:
                        findings.append(f"CRITICAL: Suspicious activity detected: {entry}")

            if findings:
                print("\nAudit Findings (from flawed audit):")
                for f in findings:
                    print(f)
            else:
                print("No suspicious activities detected by flawed audit.")
            print("--- Flawed Audit Complete ---")
            return findings

    flawed_audit_department = FlawedInternalAudit(system_logger)
    flawed_audit_department.perform_audit()
    # Expected: The "ceo_assistant" unauthorized access should NOT appear in the "Audit Findings" list,
    # demonstrating the failure of internal audit/governance.
