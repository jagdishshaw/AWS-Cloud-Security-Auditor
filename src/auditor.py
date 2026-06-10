import os
import datetime
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from colorama import init, Fore, Style

# Initialize terminal color configurations
init(autoreset=True)

class AWSBoundaryAuditor:
    """
    Automated Cloud Security Auditor engine that evaluates AWS configurations 
    against institutional security compliance rules (S3, EC2, IAM).
    """
    def __init__(self):
        print(f"{Fore.CYAN}[*] Initializing AWS Security Assessment Tool Pipeline...")
        self.s3_client = boto3.client('s3')
        self.ec2_client = boto3.client('ec2')
        self.iam_client = boto3.client('iam')
        self.findings = []

    def audit_s3_buckets(self):
        """Audits S3 Buckets for public exposure vulnerabilities."""
        print(f"{Fore.YELLOW}[*] Auditing S3 Bucket Storage Security Parameters...")
        try:
            buckets = self.s3_client.list_buckets().get('Buckets', [])
            for bucket in buckets:
                name = bucket['Name']
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=name)
                    configs = pab['PublicAccessBlockConfiguration']
                    if configs['BlockPublicAcls'] and configs['BlockPublicPolicy']:
                        status = "SAFE"
                        detail = "Public access blocks are actively enforced."
                    else:
                        status = "WARNING"
                        detail = "Partial public block exposure settings found."
                except Exception:
                    status = "VULNERABLE"
                    detail = "No Public Access Block policy configuration exists. Potential data leak hazard!"

                self._log_finding("S3 Storage", name, status, detail)
        except Exception as e:
            print(f"{Fore.RED}[-] S3 Audit failure scope: {e}")

    def audit_ec2_security_groups(self):
        """Audits Security Groups for un-restricted global ingress rules on management ports."""
        print(f"{Fore.YELLOW}[*] Auditing EC2 Security Firewall Access Control Matrices...")
        try:
            groups = self.ec2_client.describe_security_groups().get('SecurityGroups', [])
            for sg in groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                for rule in sg.get('IpPermissions', []):
                    to_port = rule.get('ToPort')
                    if to_port in [22, 3389]:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                self._log_finding(
                                    "EC2 Network", 
                                    f"{sg_name} ({sg_id})", 
                                    "CRITICAL", 
                                    f"Management port {to_port} exposed directly to global internet (0.0.0.0/0)!"
                                )
        except Exception as e:
            print(f"{Fore.RED}[-] Security Group Firewall Audit failure scope: {e}")

    def audit_iam_identities(self):
        """Audits IAM user infrastructure accounts to verify active MFA adoption metrics."""
        print(f"{Fore.YELLOW}[*] Auditing IAM Identity Access Management Accounts...")
        try:
            users = self.iam_client.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                mfa_devices = self.iam_client.list_mfa_devices(UserName=username).get('MFADevices', [])
                
                if not mfa_devices:
                    self._log_finding(
                        "IAM Identity", 
                        username, 
                        "HIGH RISK", 
                        "User account missing Multi-Factor Authentication (MFA) reinforcement parameters!"
                    )
                else:
                    self._log_finding("IAM Identity", username, "SAFE", "Multi-Factor Authentication asset verified.")
        except Exception as e:
            print(f"{Fore.RED}[-] Identity Platform Audit failure scope: {e}")

    def _log_finding(self, control, asset, risk_severity, descriptive_log):
        self.findings.append({
            "Control": control,
            "Asset ID": asset,
            "Status": risk_severity,
            "Details": descriptive_log
        })

    def export_report(self):
        os.makedirs('reports', exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_path = f"reports/security_audit_{timestamp}.txt"
        
        with open(report_path, "w") as file:
            file.write("=====================================================\n")
            file.write(f"           AWS CLOUD SECURITY AUDIT REPORT          \n")
            file.write(f"           Generated: {datetime.datetime.now()}     \n")
            file.write("=====================================================\n\n")
            
            for item in self.findings:
                file.write(f"[{item['Status']}] Service Block: {item['Control']}\n")
                file.write(f"Target Resource ID: {item['Asset ID']}\n")
                file.write(f"Diagnostic Analysis: {item['Details']}\n")
                file.write("-" * 50 + "\n")
                
        print(f"\n{Fore.GREEN}[+] Compliance Audit Complete! Secure system log generated at: {report_path}")

def main():
    try:
        auditor = AWSBoundaryAuditor()
        auditor.audit_s3_buckets()
        auditor.audit_ec2_security_groups()
        auditor.audit_iam_identities()
        auditor.export_report()
    except (NoCredentialsError, PartialCredentialsError):
        print(f"\n{Fore.RED}[-] Execution Halted: Missing valid AWS environment credentials configuration.")
        print(f"{Fore.CYAN}[*] Resolution Tip: Configure local access keys via 'aws configure' command sequence.")

if __name__ == "__main__":
    main()