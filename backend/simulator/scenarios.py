import uuid
import time
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from simulator.data_generator import pool, PROCESSES, MALWARE_FAMILIES, THREAT_ACTORS, ENCRYPTION_ALGS, CITIES, COUNTRIES, BANKS
from simulator.models import (
    CommonEnvelope, FirewallPayload, IDSPayload, VPNPayload, IAMPayload,
    InternetBankingPayload, CoreBankingPayload, UPIPayload, NEFTPayload,
    CardPayload, ATMPayload, BeneficiaryPayload, EndpointPayload,
    SIEMPayload, ThreatIntelPayload, QuantumPayload
)

# Helper to format ISO UTC timestamps
def format_utc(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

class ScheduledEvent:
    def __init__(self, time_offset_seconds: float, event_type: str, source_system: str, severity: str,
                 correlation_id: str, payload_builder):
        self.time_offset = time_offset_seconds
        self.event_type = event_type
        self.source_system = source_system
        self.severity = severity
        self.correlation_id = correlation_id
        self.payload_builder = payload_builder
        self.context = {}

    def build(self, trigger_time: datetime, context: Dict[str, Any]) -> CommonEnvelope:
        payload_data = self.payload_builder(context)
        
        customer_id = context.get("customer_id")
        employee_id = context.get("employee_id")
        device_id = context.get("device_id")
        session_id = context.get("session_id")
        ip_address = context.get("ip_address")

        return CommonEnvelope(
            event_id=str(uuid.uuid4()),
            event_type=self.event_type,
            source_system=self.source_system,
            timestamp=format_utc(trigger_time),
            severity=self.severity,
            correlation_id=self.correlation_id,
            customer_id=customer_id,
            employee_id=employee_id,
            device_id=device_id,
            session_id=session_id,
            ip_address=ip_address,
            raw_payload=payload_data.model_dump()
        )

# Helper: Enforce banking rules & balance calculations
def process_debit(customer_id: str, amount: float, preferred_status: str = "APPROVED") -> tuple:
    """Checks customer balance and returns (balance_before, balance_after, final_status)."""
    cust = next((c for c in pool.customers if c["customer_id"] == customer_id), None)
    if not cust:
        return 0.0, 0.0, "DECLINED"
    
    # Avoid zero-value transactions
    if amount <= 0:
        amount = 100.00
        
    avail_balance = cust["balance"] + cust.get("overdraft_limit", 0.0)
    
    if amount > avail_balance:
        return cust["balance"], cust["balance"], "DECLINED"
    
    balance_before = cust["balance"]
    final_status = preferred_status
    
    # Large transfers require manual approval or fail
    if amount >= 1000000.0: # > 10 Lakhs
        final_status = "PENDING"
        
    if final_status in ["APPROVED", "PENDING"]:
        cust["balance"] = round(cust["balance"] - amount, 2)
        
    balance_after = cust["balance"]
    return balance_before, balance_after, final_status

# Helper: Process ATM cash reserves
def process_atm_dispense(atm_id: str, amount: float) -> str:
    atm = next((a for a in pool.atms if a["atm_id"] == atm_id), None)
    if not atm:
        return "DECLINED"
    if atm["cash_reserve"] >= amount:
        atm["cash_reserve"] = round(atm["cash_reserve"] - amount, 2)
        return "APPROVED"
    return "DECLINED"


# --- NORMAL SCENARIOS (DIVERSE CUSTOMER BEHAVIOR WORKFLOWS) ---

def get_normal_banking_session() -> List[ScheduledEvent]:
    cust = pool.get_random_customer()
    sess_id = f"SESS_CUST_{uuid.uuid4().hex[:8].upper()}"
    corr_id = f"CORR_NORM_BANK_{uuid.uuid4().hex[:8].upper()}"
    
    context = {
        "customer_id": cust["customer_id"],
        "device_id": cust["device_id"],
        "session_id": sess_id,
        "ip_address": cust["typical_ip"],
        "account_number": cust["account_number"],
        "upi_id": cust["upi_id"],
        "card_number": cust["card_number"],
        "beneficiaries": cust["beneficiaries"],
        "city": cust["city"]
    }
    
    events = []
    t = 0.0

    # Common steps: Firewall Allow -> IAM Login -> Internet Banking Login
    events.append(ScheduledEvent(t, "firewall", "Perimeter Firewall", "INFO", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_PERIMETER_01",
        source_ip=ctx["ip_address"],
        destination_ip="10.0.1.12",
        source_port=random.randint(49152, 65535),
        destination_port=443,
        protocol="HTTPS",
        action="ALLOW",
        rule_id="RULE_ALLOW_HTTPS_EXT",
        interface="eth0",
        bytes_sent=random.randint(500, 2000),
        bytes_received=random.randint(2000, 8000),
        session_id=ctx["session_id"]
    )))
    
    t += 1.0
    events.append(ScheduledEvent(t, "iam", "IAM Authentication Services", "INFO", corr_id, lambda ctx: IAMPayload(
        user_id=ctx["customer_id"],
        username=cust["name"].lower().replace(" ", "_"),
        user_type="CUSTOMER",
        login_status="SUCCESS",
        authentication_method="PASSWORD",
        mfa_result="SKIPPED",
        device_id=ctx["device_id"],
        ip_address=ctx["ip_address"],
        session_id=ctx["session_id"]
    )))
    
    t += 1.0
    events.append(ScheduledEvent(t, "internet_banking", "Internet Banking Portal", "INFO", corr_id, lambda ctx: InternetBankingPayload(
        customer_id=ctx["customer_id"],
        account_number=ctx["account_number"],
        device_id=ctx["device_id"],
        browser=cust["browser"],
        operating_system=cust["operating_system"],
        ip_address=ctx["ip_address"],
        gps_location=f"{random.uniform(8.0, 37.0):.4f},{random.uniform(68.0, 97.0):.4f}",
        login_status="SUCCESS",
        session_id=ctx["session_id"]
    )))

    # Determine diverse behavior:
    # 40% read_only (balance check only in UI, no financial txn)
    # 25% upi transfer
    # 20% neft transfer (adds beneficiary first!)
    # 10% bill payment
    # 5% salary deposit / interest credit (deposits funds!)
    behavior = random.choices(
        ["read_only", "upi_transfer", "neft_transfer", "bill_payment", "deposit_credit"],
        weights=[0.40, 0.25, 0.20, 0.10, 0.05],
        k=1
    )[0]

    if behavior == "read_only":
        # Just check balance/profile and log out
        t += 2.0
        # No Core Banking transaction event created for balance checks to avoid 0 amounts.
        # We just log out after 2 seconds.
        pass

    elif behavior == "upi_transfer":
        t += 2.0
        amt = round(random.uniform(50.0, min(cust["balance"] + 1000.0, 50000.0)), 2)
        def upi_builder(ctx):
            bal_before, bal_after, final_status = process_debit(ctx["customer_id"], amt)
            merch = pool.get_random_merchant()
            return UPIPayload(
                transaction_id=f"TXN_UPI_{uuid.uuid4().hex[:8].upper()}",
                upi_id=ctx["upi_id"],
                customer_id=ctx["customer_id"],
                sender_account=ctx["account_number"],
                receiver_upi=f"pay.{merch['name'].lower().replace(' ', '')}@okaxis",
                receiver_bank="Axis Bank",
                amount=amt,
                device_id=ctx["device_id"],
                ip_address=ctx["ip_address"],
                merchant=merch["name"],
                status=final_status
            )
        events.append(ScheduledEvent(t, "upi", "UPI Node Manager", "INFO", corr_id, upi_builder))

    elif behavior == "neft_transfer":
        # First, add a new beneficiary (Workflow sequence!)
        t += 2.0
        new_ben = {
            "beneficiary_id": f"BEN_{uuid.uuid4().hex[:6].upper()}",
            "name": f"Recipient {random.randint(100, 999)}",
            "account_number": f"{random.randint(100000000, 999999999)}",
            "bank": random.choice(BANKS)["name"],
            "ifsc": f"SBIN0{random.randint(100000, 999999)}"
        }
        # Add to customer list in-memory
        cust["beneficiaries"].append(new_ben)
        
        events.append(ScheduledEvent(t, "beneficiary", "Core Banking Portal", "INFO", corr_id, lambda ctx: BeneficiaryPayload(
            customer_id=ctx["customer_id"],
            beneficiary_id=new_ben["beneficiary_id"],
            beneficiary_name=new_ben["name"],
            account_number=new_ben["account_number"],
            ifsc=new_ben["ifsc"],
            action="ADD"
        )))

        # Then, perform NEFT transfer (2s later)
        t += 2.0
        amt = round(random.uniform(5000.0, min(cust["balance"] + 5000.0, 500000.0)), 2)
        def neft_builder(ctx):
            bal_before, bal_after, final_status = process_debit(ctx["customer_id"], amt)
            return NEFTPayload(
                transaction_id=f"TXN_NEFT_{uuid.uuid4().hex[:8].upper()}",
                account_number=ctx["account_number"],
                beneficiary_account=new_ben["account_number"],
                beneficiary_bank=new_ben["bank"],
                ifsc=new_ben["ifsc"],
                amount=amt,
                channel=random.choice(["NEFT", "IMPS"]),
                transaction_status=final_status
            )
        events.append(ScheduledEvent(t, "neft_rtgs_imps", "Payment Processing Engine", "INFO", corr_id, neft_builder))

    elif behavior == "bill_payment":
        t += 2.0
        amt = round(random.uniform(200.0, min(cust["balance"] + 200.0, 15000.0)), 2)
        def core_builder(ctx):
            bal_before, bal_after, final_status = process_debit(ctx["customer_id"], amt)
            return CoreBankingPayload(
                transaction_id=f"TXN_CORE_{uuid.uuid4().hex[:8].upper()}",
                account_number=ctx["account_number"],
                customer_id=ctx["customer_id"],
                transaction_type="TRANSFER",
                amount=amt,
                currency="INR",
                balance_before=bal_before,
                balance_after=bal_after,
                branch=cust["branch"],
                channel="NET_BANKING",
                status=final_status
            )
        events.append(ScheduledEvent(t, "core_banking", "Core Banking Host", "INFO", corr_id, core_builder))

    elif behavior == "deposit_credit":
        t += 2.0
        amt = round(random.uniform(5000.0, 100000.0), 2)
        def deposit_builder(ctx):
            # Deposit logic (adds to balance!)
            balance_before = cust["balance"]
            cust["balance"] = round(cust["balance"] + amt, 2)
            balance_after = cust["balance"]
            
            return CoreBankingPayload(
                transaction_id=f"TXN_CORE_{uuid.uuid4().hex[:8].upper()}",
                account_number=ctx["account_number"],
                customer_id=ctx["customer_id"],
                transaction_type="DEPOSIT",
                amount=amt,
                currency="INR",
                balance_before=balance_before,
                balance_after=balance_after,
                branch=cust["branch"],
                channel="NET_BANKING",
                status="APPROVED"
            )
        events.append(ScheduledEvent(t, "core_banking", "Core Banking Host", "INFO", corr_id, deposit_builder))

    # Context binding
    for ev in events:
        ev.context = context

    return events

def get_normal_employee_session() -> List[ScheduledEvent]:
    emp = pool.get_random_employee()
    sess_id = f"SESS_EMP_{uuid.uuid4().hex[:8].upper()}"
    corr_id = f"CORR_NORM_EMP_{uuid.uuid4().hex[:8].upper()}"
    
    context = {
        "employee_id": emp["employee_id"],
        "device_id": emp["device_id"],
        "session_id": sess_id,
        "ip_address": emp["typical_ip"]
    }
    
    events = []
    t = 0.0
    
    # Step 1: Firewall Allow
    events.append(ScheduledEvent(t, "firewall", "Corporate Firewall", "INFO", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_CORP_INTERNAL",
        source_ip=ctx["ip_address"],
        destination_ip="10.20.1.1",
        source_port=random.randint(49152, 65535),
        destination_port=443,
        protocol="HTTPS",
        action="ALLOW",
        rule_id="RULE_CORP_INT",
        interface="port2",
        bytes_sent=random.randint(1000, 5000),
        bytes_received=random.randint(5000, 25000),
        session_id=ctx["session_id"]
    )))
    
    # Step 2: IAM Login Success (1s later)
    t += 1.0
    events.append(ScheduledEvent(t, "iam", "Active Directory Services", "INFO", corr_id, lambda ctx: IAMPayload(
        user_id=ctx["employee_id"],
        username=emp["username"],
        user_type="EMPLOYEE",
        login_status="SUCCESS",
        authentication_method=emp["auth_method"],
        mfa_result="SUCCESS" if emp["auth_method"] == "MFA" else "SKIPPED",
        device_id=ctx["device_id"],
        ip_address=ctx["ip_address"],
        session_id=ctx["session_id"]
    )))
    
    # Step 3: Endpoint normal telemetry (2s later)
    t += 2.0
    events.append(ScheduledEvent(t, "endpoint", "EDR Sensor Agent", "INFO", corr_id, lambda ctx: EndpointPayload(
        endpoint_id=f"EDR_{ctx['device_id']}",
        device_id=ctx["device_id"],
        user=emp["username"],
        process_name=random.choice([p for p in PROCESSES if p["name"] not in ["jackpot_helper.exe", "invoice.pdf.exe"]])["name"],
        process_hash=random.choice(PROCESSES)["hash"],
        malware_name=None,
        detection_status="CLEAN",
        cpu_usage=round(random.uniform(1.0, 15.0), 2),
        memory_usage=round(random.uniform(5.0, 45.0), 2)
    )))

    for ev in events:
        ev.context = context
        
    return events

def get_normal_atm_withdrawal() -> List[ScheduledEvent]:
    cust = pool.get_random_customer()
    atm = pool.get_random_atm()
    corr_id = f"CORR_NORM_ATM_{uuid.uuid4().hex[:8].upper()}"
    amt = float(random.choice([500, 1000, 2000, 5000, 10000]))
    
    context = {
        "customer_id": cust["customer_id"],
        "card_number": cust["card_number"],
        "device_id": f"ATM_DEV_{atm['atm_id']}",
        "ip_address": f"192.168.99.{random.randint(10, 50)}"
    }
    
    def atm_builder(ctx):
        final_dispense = process_atm_dispense(atm["atm_id"], amt)
        if final_dispense == "APPROVED":
            bal_before, bal_after, final_status = process_debit(ctx["customer_id"], amt)
        else:
            bal_before, bal_after, final_status = cust["balance"], cust["balance"], "DECLINED"
            
        return ATMPayload(
            atm_id=atm["atm_id"],
            transaction_id=f"TXN_ATM_{uuid.uuid4().hex[:8].upper()}",
            card_number=ctx["card_number"],
            customer_id=ctx["customer_id"],
            transaction_type="WITHDRAWAL",
            amount=amt,
            balance=bal_after,
            atm_location=atm["location"],
            status=final_status
        )
    
    ev = ScheduledEvent(0.0, "atm", "ATM Host Switch", "INFO", corr_id, atm_builder)
    ev.context = context
    return [ev]

def get_normal_card_transaction() -> List[ScheduledEvent]:
    cust = pool.get_random_customer()
    merch = pool.get_random_merchant()
    corr_id = f"CORR_NORM_CARD_{uuid.uuid4().hex[:8].upper()}"
    amt = round(random.uniform(100.0, min(cust["balance"] + 1000.0, cust["avg_spend"] * 2.0)), 2)
    
    context = {
        "customer_id": cust["customer_id"],
        "card_number": cust["card_number"],
        "device_id": cust["device_id"],
        "ip_address": cust["typical_ip"]
    }
    
    def card_builder(ctx):
        bal_before, bal_after, final_status = process_debit(ctx["customer_id"], amt)
        return CardPayload(
            transaction_id=f"TXN_CARD_{uuid.uuid4().hex[:8].upper()}",
            masked_card_number=ctx["card_number"],
            merchant_id=merch["merchant_id"],
            merchant_category=merch["category"],
            pos_terminal=f"POS_{uuid.uuid4().hex[:8].upper()}",
            country=merch["country"],
            city=merch["city"],
            amount=amt,
            currency="INR",
            approval_code=f"{random.randint(100000, 999999)}" if final_status == "APPROVED" else None
        )
    
    ev = ScheduledEvent(0.0, "card", "Visa/Mastercard Gateway", "INFO", corr_id, card_builder)
    ev.context = context
    return [ev]


# --- ATTACK SCENARIOS (WITH BANKING CONSTRAINTS & DEFENSE logic) ---

# 1. Credential Theft
def get_attack_credential_theft() -> List[ScheduledEvent]:
    emp = pool.get_random_employee()
    corr_id = f"CORR_ATTACK_CRED_THEFT_{uuid.uuid4().hex[:8].upper()}"
    cust = pool.get_random_customer()
    new_ip = "185.220.101.4"  # Tor Exit Node
    new_device = "DEV_EMP_9911"
    beneficiary_id = "BEN_THEFT_9901"
    
    context = {
        "employee_id": emp["employee_id"],
        "device_id": emp["device_id"],
        "ip_address": emp["typical_ip"],
        "session_id": f"SESS_EMP_{uuid.uuid4().hex[:6].upper()}",
        "customer_id": cust["customer_id"]
    }
    
    events = []
    t = 0.0

    # Step 1: Normal Firewall Allow
    events.append(ScheduledEvent(t, "firewall", "Corporate Firewall", "INFO", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_CORP_INTERNAL",
        source_ip=ctx["ip_address"],
        destination_ip="10.20.1.1",
        source_port=random.randint(49152, 65535),
        destination_port=443,
        protocol="HTTPS",
        action="ALLOW",
        rule_id="RULE_CORP_INT",
        interface="port2",
        bytes_sent=1500,
        bytes_received=6000,
        session_id=ctx["session_id"]
    )))

    # Step 2: Employee normal login
    t += 2.0
    events.append(ScheduledEvent(t, "iam", "Active Directory Services", "INFO", corr_id, lambda ctx: IAMPayload(
        user_id=ctx["employee_id"],
        username=emp["username"],
        user_type="EMPLOYEE",
        login_status="SUCCESS",
        authentication_method=emp["auth_method"],
        mfa_result="SUCCESS" if emp["auth_method"] == "MFA" else "SKIPPED",
        device_id=ctx["device_id"],
        ip_address=ctx["ip_address"],
        session_id=ctx["session_id"]
    )))

    # Step 3: EDR alert: credential dumping detected
    t += 3.0
    events.append(ScheduledEvent(t, "endpoint", "EDR Sensor Agent", "HIGH", corr_id, lambda ctx: EndpointPayload(
        endpoint_id=f"EDR_{ctx['device_id']}",
        device_id=ctx["device_id"],
        user=emp["username"],
        process_name="lsass.exe",
        process_hash="9f3a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
        malware_name="CredentialDumper.Mimikatz",
        detection_status="ALERTED",
        cpu_usage=88.5,
        memory_usage=72.1
    )))

    # Step 4: Firewall blocks command-and-control connection
    t += 2.0
    events.append(ScheduledEvent(t, "firewall", "Corporate Firewall", "MEDIUM", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_CORP_INTERNAL",
        source_ip=ctx["ip_address"],
        destination_ip="198.51.100.8",
        source_port=50005,
        destination_port=4444,
        protocol="TCP",
        action="DENY",
        rule_id="RULE_BLOCK_C2",
        interface="port2",
        bytes_sent=120,
        bytes_received=0,
        session_id=ctx["session_id"]
    )))

    # Step 5: Attacker logs in from Tor Node (Unfamiliar IP) using stolen credentials
    t += 4.0
    def attacker_vpn_builder(ctx):
        ctx["ip_address"] = new_ip
        ctx["device_id"] = new_device
        ctx["session_id"] = f"SESS_EMP_{uuid.uuid4().hex[:6].upper()}"
        return VPNPayload(
            session_id=ctx["session_id"],
            user_id=ctx["employee_id"],
            employee_id=ctx["employee_id"],
            vpn_gateway="VPN_GW_EXTERNAL_02",
            source_ip=ctx["ip_address"],
            country="Germany",
            device_id=ctx["device_id"],
            login_time=format_utc(datetime.now(timezone.utc)),
            mfa_status="BYPASSED",
            authentication_status="SUCCESS"
        )
    events.append(ScheduledEvent(t, "vpn", "VPN Gateway Server", "HIGH", corr_id, attacker_vpn_builder))

    # Step 6: IAM authentication bypass log
    t += 1.0
    events.append(ScheduledEvent(t, "iam", "Active Directory Services", "HIGH", corr_id, lambda ctx: IAMPayload(
        user_id=ctx["employee_id"],
        username=emp["username"],
        user_type="EMPLOYEE",
        login_status="SUCCESS",
        authentication_method="MFA",
        mfa_result="BYPASSED",
        device_id=ctx["device_id"],
        ip_address=ctx["ip_address"],
        session_id=ctx["session_id"],
        failure_reason="MFA bypass via session hijacking"
    )))

    # Step 7: Attacker adds high-value beneficiary in banking backend
    t += 3.0
    events.append(ScheduledEvent(t, "beneficiary", "Core Banking Portal", "HIGH", corr_id, lambda ctx: BeneficiaryPayload(
        customer_id=ctx["customer_id"],
        beneficiary_id=beneficiary_id,
        beneficiary_name="Unknown Mule Account",
        account_number="990011223344",
        ifsc="MAHB0000888",
        action="ADD"
    )))

    # Step 8: High value transfer (defense: Blocked/Suspended due to preceding alerts!)
    t += 2.0
    # Dynamically scale transfer amount to steal 95% of customer's funds
    # Capped at balance to enforce available balance rules
    amt = round(cust["balance"] * 0.95, 2)
    if amt <= 0:
        amt = 1000.0
        
    def transfer_builder(ctx):
        # Attacker tries to steal funds.
        # Defense logic: Since SIEM triggered earlier alerts (LSASS dump, Tor VPN, MFA bypass),
        # the transaction is flagged and marked as PENDING for review, rather than automatically APPROVED.
        bal_before, bal_after, final_status = process_debit(ctx["customer_id"], amt, preferred_status="PENDING")
        return CoreBankingPayload(
            transaction_id=f"TXN_CORE_{uuid.uuid4().hex[:8].upper()}",
            account_number=cust["account_number"],
            customer_id=ctx["customer_id"],
            transaction_type="TRANSFER",
            amount=amt,
            currency="INR",
            balance_before=bal_before,
            balance_after=bal_after,
            branch=cust["branch"],
            channel="BRANCH",
            status=final_status
        )
    events.append(ScheduledEvent(t, "core_banking", "Core Banking Host", "CRITICAL", corr_id, transfer_builder))

    # Step 9: SIEM Alert
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "CRITICAL", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="Core Banking Host",
        severity="CRITICAL",
        event_category="FRAUD_ATTACK",
        rule_name="Suspicious Employee Login and High Value Customer Account Transfer held for approval"
    )))

    for ev in events:
        ev.context = context
    return events

# 2. Malware Infection
def get_attack_malware_infection() -> List[ScheduledEvent]:
    emp = pool.get_random_employee()
    corr_id = f"CORR_ATTACK_MALWARE_{uuid.uuid4().hex[:8].upper()}"
    c2_ip = "198.51.100.45"
    db_server = "SRV_SQL_CORE"
    archive_id = "ARC_CUST_RECORDS"
    
    context = {
        "employee_id": emp["employee_id"],
        "device_id": emp["device_id"],
        "ip_address": emp["typical_ip"],
        "session_id": f"SESS_EMP_{uuid.uuid4().hex[:6].upper()}"
    }
    
    events = []
    t = 0.0

    # Step 1: Firewall allows download
    events.append(ScheduledEvent(t, "firewall", "Perimeter Firewall", "INFO", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_PERIMETER_01",
        source_ip=ctx["ip_address"],
        destination_ip="93.184.216.34",
        source_port=random.randint(49152, 65535),
        destination_port=443,
        protocol="HTTPS",
        action="ALLOW",
        rule_id="RULE_ALLOW_OUTBOUND",
        interface="eth0",
        bytes_sent=4500,
        bytes_received=2500000,
        session_id=ctx["session_id"]
    )))

    # Step 2: EDR alert: malicious process executed
    t += 2.0
    events.append(ScheduledEvent(t, "endpoint", "EDR Sensor Agent", "HIGH", corr_id, lambda ctx: EndpointPayload(
        endpoint_id=f"EDR_{ctx['device_id']}",
        device_id=ctx["device_id"],
        user=emp["username"],
        process_name="invoice.pdf.exe",
        process_hash="0a2b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b",
        malware_name="Trojan.Generic",
        detection_status="ALERTED",
        cpu_usage=45.2,
        memory_usage=38.9
    )))

    # Step 3: Firewall: outbound C2 traffic allowed
    t += 2.0
    events.append(ScheduledEvent(t, "firewall", "Corporate Firewall", "HIGH", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_CORP_INTERNAL",
        source_ip=ctx["ip_address"],
        destination_ip=c2_ip,
        source_port=49912,
        destination_port=8080,
        protocol="TCP",
        action="ALLOW",
        rule_id="RULE_CORP_INT",
        interface="port2",
        bytes_sent=8400,
        bytes_received=125000,
        session_id=ctx["session_id"]
    )))

    # Step 4: Threat Intelligence Feed IOC Match
    t += 1.0
    events.append(ScheduledEvent(t, "threat_intel", "Threat Intelligence Service", "HIGH", corr_id, lambda ctx: ThreatIntelPayload(
        ioc_id=f"IOC_INTEL_{uuid.uuid4().hex[:6].upper()}",
        ioc_type="IP",
        ioc_value=c2_ip,
        threat_actor="Wizard Spider",
        malware_family="TrickBot",
        confidence_score=0.92,
        first_seen="2026-05-10T12:00:00Z",
        last_seen=format_utc(datetime.now(timezone.utc)),
        mitre_attack_mapping="Command and Control (T1071)"
    )))

    # Step 5: Database access (read archive)
    t += 3.0
    events.append(ScheduledEvent(t, "quantum_hndl", "HNDL Audit System", "HIGH", corr_id, lambda ctx: QuantumPayload(
        server_id=db_server,
        archive_id=archive_id,
        encryption_algorithm="AES-256",
        data_volume="12.4 GB",
        read_duration=180,
        outbound_destination=c2_ip,
        transfer_size="12.4 GB",
        encryption_status="LEGACY_VULNERABLE"
    )))

    # Step 6: SIEM Alert
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "CRITICAL", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="EDR Sensor Agent",
        severity="CRITICAL",
        event_category="MALWARE_EXFILTRATION",
        rule_name="EDR Malware Detection followed by Outbound Exfiltration to Wizard Spider C2"
    )))

    for ev in events:
        ev.context = context
    return events

# 3. Brute Force Attack
def get_attack_brute_force() -> List[ScheduledEvent]:
    emp = pool.get_random_employee()
    corr_id = f"CORR_ATTACK_BRUTE_{uuid.uuid4().hex[:8].upper()}"
    attacker_ip = "203.0.113.88"
    
    context = {
        "employee_id": emp["employee_id"],
        "device_id": emp["device_id"],
        "ip_address": attacker_ip,
        "session_id": f"SESS_ATTACK_{uuid.uuid4().hex[:6].upper()}"
    }
    
    events = []
    t = 0.0

    # Step 1: Firewall allow external to IAM Gateway
    events.append(ScheduledEvent(t, "firewall", "Perimeter Firewall", "INFO", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_PERIMETER_01",
        source_ip=ctx["ip_address"],
        destination_ip="10.20.1.1",
        source_port=random.randint(49000, 65000),
        destination_port=443,
        protocol="HTTPS",
        action="ALLOW",
        rule_id="RULE_ALLOW_HTTPS_EXT",
        interface="eth0",
        bytes_sent=1200,
        bytes_received=4500,
        session_id=ctx["session_id"]
    )))

    # Step 2-4: Repeated failed logins
    for attempt in range(5):
        t += 0.5
        events.append(ScheduledEvent(t, "iam", "Active Directory Services", "MEDIUM", corr_id, lambda ctx, att=attempt: IAMPayload(
            user_id=ctx["employee_id"],
            username=emp["username"],
            user_type="EMPLOYEE",
            login_status="FAILURE",
            authentication_method="PASSWORD",
            mfa_result="SKIPPED",
            device_id=ctx["device_id"],
            ip_address=ctx["ip_address"],
            session_id=ctx["session_id"],
            failure_reason="Invalid Credentials"
        )))

    # Step 5: IDS alert for brute force
    t += 1.0
    events.append(ScheduledEvent(t, "ids_ips", "DMZ IDS Sensor", "HIGH", corr_id, lambda ctx: IDSPayload(
        sensor_id="IDS_DMZ_01",
        source_ip=ctx["ip_address"],
        destination_ip="10.20.1.1",
        signature_id="SIG_HTTPS_BRUTE_FORCE",
        attack_name="HTTPS Password Spraying / Brute Force Attempt",
        severity="HIGH",
        confidence=0.88,
        protocol="HTTPS",
        action="ALERTED",
        mitre_technique="Brute Force (T1110)"
    )))

    # Step 6: Successful login (Brute force succeeds)
    t += 2.0
    events.append(ScheduledEvent(t, "iam", "Active Directory Services", "HIGH", corr_id, lambda ctx: IAMPayload(
        user_id=ctx["employee_id"],
        username=emp["username"],
        user_type="EMPLOYEE",
        login_status="SUCCESS",
        authentication_method="PASSWORD",
        mfa_result="SKIPPED",
        device_id=ctx["device_id"],
        ip_address=ctx["ip_address"],
        session_id=ctx["session_id"]
    )))

    # Step 7: Privilege Escalation command
    t += 2.0
    events.append(ScheduledEvent(t, "endpoint", "EDR Sensor Agent", "CRITICAL", corr_id, lambda ctx: EndpointPayload(
        endpoint_id=f"EDR_{ctx['device_id']}",
        device_id=ctx["device_id"],
        user=emp["username"],
        process_name="cmd.exe",
        process_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        malware_name="PrivilegeEscalation.Exploit",
        detection_status="ALERTED",
        cpu_usage=90.0,
        memory_usage=55.0
    )))

    # Step 8: SIEM Alert
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "CRITICAL", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="Active Directory Services",
        severity="CRITICAL",
        event_category="IDENTITY_ABUSE",
        rule_name="Brute Force Attack Followed by Privilege Escalation"
    )))

    for ev in events:
        ev.context = context
    return events

# 4. Insider Threat (HNDL Archive Export)
def get_attack_insider_threat() -> List[ScheduledEvent]:
    emp = pool.get_random_employee()
    corr_id = f"CORR_INSIDER_HNDL_{uuid.uuid4().hex[:8].upper()}"
    destination_storage = "8.8.8.8"
    
    context = {
        "employee_id": emp["employee_id"],
        "device_id": emp["device_id"],
        "ip_address": "122.160.10.8",  # Indian residential IP (Remote)
        "session_id": f"SESS_VPN_{uuid.uuid4().hex[:6].upper()}"
    }
    
    events = []
    t = 0.0

    # Step 1: Remote VPN Login at Anomalous Hour (2 AM)
    events.append(ScheduledEvent(t, "vpn", "VPN Gateway Server", "MEDIUM", corr_id, lambda ctx: VPNPayload(
        session_id=ctx["session_id"],
        user_id=ctx["employee_id"],
        employee_id=ctx["employee_id"],
        vpn_gateway="VPN_GW_PRIMARY",
        source_ip=ctx["ip_address"],
        country="India",
        device_id=ctx["device_id"],
        login_time=format_utc(datetime.now(timezone.utc) - timedelta(hours=1)),
        mfa_status="ENABLED",
        authentication_status="SUCCESS"
    )))

    # Step 2: AD Login Successful
    t += 1.0
    events.append(ScheduledEvent(t, "iam", "Active Directory Services", "INFO", corr_id, lambda ctx: IAMPayload(
        user_id=ctx["employee_id"],
        username=emp["username"],
        user_type="EMPLOYEE",
        login_status="SUCCESS",
        authentication_method="MFA",
        mfa_result="SUCCESS",
        device_id=ctx["device_id"],
        ip_address=ctx["ip_address"],
        session_id=ctx["session_id"]
    )))

    # Step 3: Database query spike (EDR endpoint logs command shell activity)
    t += 3.0
    events.append(ScheduledEvent(t, "endpoint", "EDR Sensor Agent", "MEDIUM", corr_id, lambda ctx: EndpointPayload(
        endpoint_id=f"EDR_{ctx['device_id']}",
        device_id=ctx["device_id"],
        user=emp["username"],
        process_name="cmd.exe",
        process_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        malware_name=None,
        detection_status="CLEAN",
        cpu_usage=35.0,
        memory_usage=20.0
    )))

    # Step 4: Quantum HNDL Access event (Legacy RSA encryption database archive read)
    t += 2.0
    events.append(ScheduledEvent(t, "quantum_hndl", "HNDL Audit System", "HIGH", corr_id, lambda ctx: QuantumPayload(
        server_id="SRV_SQL_CORE",
        archive_id="ARC_KEY_DB_2026",
        encryption_algorithm="Legacy RSA-2048 / AES-256",
        data_volume="50 GB",
        read_duration=600,
        outbound_destination=destination_storage,
        transfer_size="50 GB",
        encryption_status="LEGACY_VULNERABLE"
    )))

    # Step 5: Firewall: large outbound traffic allowed (defense: flag high read exfil)
    t += 3.0
    events.append(ScheduledEvent(t, "firewall", "Perimeter Firewall", "HIGH", corr_id, lambda ctx: FirewallPayload(
        firewall_device_id="FW_PERIMETER_01",
        source_ip="10.20.10.15",
        destination_ip=destination_storage,
        source_port=1433,
        destination_port=443,
        protocol="HTTPS",
        action="ALLOW",
        rule_id="RULE_ALLOW_CLOUDSYNC",
        interface="eth0",
        bytes_sent=53687091200,
        bytes_received=1048576,
        session_id=ctx["session_id"]
    )))

    # Step 6: SIEM Alert
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "HIGH", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="HNDL Audit System",
        severity="HIGH",
        event_category="INSIDER_THREAT",
        rule_name="Anomalous Large Quantum Archive Export by DBA at 2:00 AM"
    )))

    for ev in events:
        ev.context = context
    return events

# 5. Account Takeover & Impossible Travel
def get_attack_account_takeover() -> List[ScheduledEvent]:
    cust = pool.get_random_customer()
    corr_id = f"CORR_ATO_{uuid.uuid4().hex[:8].upper()}"
    germany_ip = "45.132.88.9"
    paris_merchant = "LUXURY_PARIS"
    atm = pool.get_random_atm()
    beneficiary_id = "BEN_ATO_0481"
    
    context = {
        "customer_id": cust["customer_id"],
        "device_id": cust["device_id"],
        "ip_address": cust["typical_ip"],
        "session_id": f"SESS_CUST_{uuid.uuid4().hex[:6].upper()}",
        "account_number": cust["account_number"],
        "card_number": cust["card_number"]
    }
    
    events = []
    t = 0.0

    # Step 1: Customer logs in from India (Mumbai)
    events.append(ScheduledEvent(t, "internet_banking", "Internet Banking Portal", "INFO", corr_id, lambda ctx: InternetBankingPayload(
        customer_id=ctx["customer_id"],
        account_number=ctx["account_number"],
        device_id=ctx["device_id"],
        browser=cust["browser"],
        operating_system=cust["operating_system"],
        ip_address=ctx["ip_address"],
        gps_location="18.9750,72.8258",  # Mumbai
        login_status="SUCCESS",
        session_id=ctx["session_id"]
    )))

    # Step 2: Attacker logs in 5 minutes later from Frankfurt, Germany (Impossible Travel!)
    t += 2.0
    def Germany_login_builder(ctx):
        ctx["ip_address"] = germany_ip
        ctx["device_id"] = "DEV_ATO_9041"
        ctx["session_id"] = f"SESS_CUST_{uuid.uuid4().hex[:6].upper()}"
        return InternetBankingPayload(
            customer_id=ctx["customer_id"],
            account_number=ctx["account_number"],
            device_id=ctx["device_id"],
            browser="Firefox",
            operating_system="Windows 11",
            ip_address=ctx["ip_address"],
            gps_location="50.1109,8.6821",  # Frankfurt
            login_status="SUCCESS",
            session_id=ctx["session_id"]
        )
    events.append(ScheduledEvent(t, "internet_banking", "Internet Banking Portal", "HIGH", corr_id, Germany_login_builder))

    # Step 3: SIEM Alert - Impossible Travel
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "HIGH", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="Internet Banking Portal",
        severity="HIGH",
        event_category="IDENTITY_ABUSE",
        rule_name="Impossible Travel Detected: Customer session initiated from Frankfurt, Germany within minutes of Mumbai, India session"
    )))

    # Step 4: Beneficiary Added by attacker
    t += 2.0
    events.append(ScheduledEvent(t, "beneficiary", "Core Banking Portal", "HIGH", corr_id, lambda ctx: BeneficiaryPayload(
        customer_id=ctx["customer_id"],
        beneficiary_id=beneficiary_id,
        beneficiary_name="Unknown German Receiver",
        account_number="998800112233",
        ifsc="BARB0MUMBAI",
        action="ADD"
    )))

    # Step 5: Core Banking Transfer NEFT (defense: Flagged & Suspended due to Impossible Travel!)
    t += 2.0
    # Dynamically scale transfer amount to steal 85% of customer's funds
    amt = round(cust["balance"] * 0.85, 2)
    if amt <= 0:
        amt = 500.0
        
    def neft_transfer_builder(ctx):
        # Attacker tries to transfer.
        # Defense logic: Suspended due to preceding Impossible Travel flag
        bal_before, bal_after, final_status = process_debit(ctx["customer_id"], amt, preferred_status="PENDING")
        return NEFTPayload(
            transaction_id=f"TXN_NEFT_{uuid.uuid4().hex[:8].upper()}",
            account_number=ctx["account_number"],
            beneficiary_account="998800112233",
            beneficiary_bank="Bank of Baroda",
            ifsc="BARB0MUMBAI",
            amount=amt,
            channel="NEFT",
            transaction_status=final_status
        )
    events.append(ScheduledEvent(t, "neft_rtgs_imps", "Payment Processing Engine", "HIGH", corr_id, neft_transfer_builder))

    # Step 6: Card present in Paris, France (Card Not Present Online attempt) - Declined due to active fraud block!
    t += 2.0
    def card_builder(ctx):
        # Transaction is declined because card is frozen after fraud check
        return CardPayload(
            transaction_id=f"TXN_CARD_{uuid.uuid4().hex[:8].upper()}",
            masked_card_number=ctx["card_number"],
            merchant_id="MERCH_LUX_PARIS",
            merchant_category="LUXURY",
            pos_terminal=f"POS_PARIS_{uuid.uuid4().hex[:4].upper()}",
            country="France",
            city="Paris",
            amount=2000.00,
            currency="EUR",
            approval_code=None
        )
    events.append(ScheduledEvent(t, "card", "Visa/Mastercard Gateway", "HIGH", corr_id, card_builder))

    # Step 7: Physical ATM withdrawal attempt back in Mumbai - Denied due to German session active block
    t += 2.0
    def atm_builder(ctx):
        # Denied due to active threat block
        return ATMPayload(
            atm_id=atm["atm_id"],
            transaction_id=f"TXN_ATM_{uuid.uuid4().hex[:8].upper()}",
            card_number=ctx["card_number"],
            customer_id=ctx["customer_id"],
            transaction_type="WITHDRAWAL",
            amount=10000.0,
            balance=cust["balance"],
            atm_location=atm["location"],
            status="DECLINED"
        )
    events.append(ScheduledEvent(t, "atm", "ATM Host Switch", "HIGH", corr_id, atm_builder))

    # Step 8: SIEM Critical Alert
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "CRITICAL", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="ATM Host Switch",
        severity="CRITICAL",
        event_category="FRAUD_ATTACK",
        rule_name="Coordinated Multi-Channel Fraud and Account Takeover blocked"
    )))

    for ev in events:
        ev.context = context
    return events

# 6. Card Fraud
def get_attack_card_fraud() -> List[ScheduledEvent]:
    cust = pool.get_random_customer()
    corr_id = f"CORR_CARD_FRAUD_{uuid.uuid4().hex[:8].upper()}"
    
    context = {
        "customer_id": cust["customer_id"],
        "card_number": cust["card_number"]
    }
    
    events = []
    t = 0.0

    # Step 1: Normal transaction Mumbai
    events.append(ScheduledEvent(t, "card", "Visa/Mastercard Gateway", "INFO", corr_id, lambda ctx: CardPayload(
        transaction_id=f"TXN_CARD_{uuid.uuid4().hex[:8].upper()}",
        masked_card_number=ctx["card_number"],
        merchant_id="MERCH_MUM_CAFE",
        merchant_category="FOOD",
        pos_terminal="POS_MUM_012",
        country="India",
        city="Mumbai",
        amount=1200.00,
        currency="INR",
        approval_code="102938"
    )))

    # Step 2: High value international purchase in Milan, Italy (10 minutes later) - Declined due to location check
    t += 2.0
    events.append(ScheduledEvent(t, "card", "Visa/Mastercard Gateway", "HIGH", corr_id, lambda ctx: CardPayload(
        transaction_id=f"TXN_CARD_{uuid.uuid4().hex[:8].upper()}",
        masked_card_number=ctx["card_number"],
        merchant_id="MERCH_GUCCI_MILAN",
        merchant_category="LUXURY",
        pos_terminal="POS_MILAN_044",
        country="Italy",
        city="Milan",
        amount=250000.00,
        currency="INR",
        approval_code=None  # Declined
    )))

    # Step 3: Repeated declines at online gaming site (UK)
    t += 2.0
    events.append(ScheduledEvent(t, "card", "Visa/Mastercard Gateway", "HIGH", corr_id, lambda ctx: CardPayload(
        transaction_id=f"TXN_CARD_{uuid.uuid4().hex[:8].upper()}",
        masked_card_number=ctx["card_number"],
        merchant_id="MERCH_GAMING_UK",
        merchant_category="GAMING",
        pos_terminal="CNP_ONLINE_883",
        country="United Kingdom",
        city="London",
        amount=5000.00,
        currency="GBP",
        approval_code=None  # Declined
    )))

    # Step 4: SIEM Alert
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "HIGH", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="Visa/Mastercard Gateway",
        severity="HIGH",
        event_category="FRAUD_ATTACK",
        rule_name="Multiple Country Card Transactions Velocity Abuse"
    )))

    for ev in events:
        ev.context = context
    return events

# 7. ATM Jackpotting
def get_attack_atm_jackpotting() -> List[ScheduledEvent]:
    atm = pool.get_random_atm()
    tech = pool.get_random_employee() # Maintenance tech role
    corr_id = f"CORR_ATM_JACKPOT_{uuid.uuid4().hex[:8].upper()}"
    
    context = {
        "employee_id": tech["employee_id"],
        "device_id": f"ATM_DEV_{atm['atm_id']}",
        "ip_address": f"192.168.99.{random.randint(10, 50)}",
        "session_id": f"SESS_ATM_MAINT_{uuid.uuid4().hex[:6].upper()}"
    }
    
    events = []
    t = 0.0

    # Step 1: Maintenance Login
    events.append(ScheduledEvent(t, "iam", "ATM Local Authentication", "INFO", corr_id, lambda ctx: IAMPayload(
        user_id=ctx["employee_id"],
        username=tech["username"],
        user_type="EMPLOYEE",
        login_status="SUCCESS",
        authentication_method="PASSWORD",
        mfa_result="SKIPPED",
        device_id=ctx["device_id"],
        ip_address=ctx["ip_address"],
        session_id=ctx["session_id"]
    )))

    # Step 2: EDR alert: unauthorized firmware execution on ATM
    t += 2.0
    events.append(ScheduledEvent(t, "endpoint", "ATM EDR Agent", "CRITICAL", corr_id, lambda ctx: EndpointPayload(
        endpoint_id=f"EDR_{ctx['device_id']}",
        device_id=ctx["device_id"],
        user="SYSTEM",
        process_name="jackpot_helper.exe",
        process_hash="ffea7762bc1234567890abcdef1234567890abcdef1234567890abcdef1234",
        malware_name="JackpotMalware.Ploutus",
        detection_status="ALERTED",
        cpu_usage=92.4,
        memory_usage=81.0
    )))

    # Step 3: ATM Transaction - Out of band Cash Out Withdrawal
    t += 3.0
    amt_cash = 100000.0
    def atm_builder1(ctx):
        final_dispense = process_atm_dispense(atm["atm_id"], amt_cash)
        return ATMPayload(
            atm_id=atm["atm_id"],
            transaction_id=f"TXN_ATM_{uuid.uuid4().hex[:8].upper()}",
            card_number="XXXXXXXXXXXX0000",
            customer_id="SYSTEM_CASH_OUT",
            transaction_type="WITHDRAWAL",
            amount=amt_cash,
            balance=0.0,
            atm_location=atm["location"],
            status=final_dispense
        )
    events.append(ScheduledEvent(t, "atm", "ATM Host Switch", "HIGH", corr_id, atm_builder1))

    # Step 4: Another Cash Out Withdrawal
    t += 2.0
    def atm_builder2(ctx):
        final_dispense = process_atm_dispense(atm["atm_id"], amt_cash)
        return ATMPayload(
            atm_id=atm["atm_id"],
            transaction_id=f"TXN_ATM_{uuid.uuid4().hex[:8].upper()}",
            card_number="XXXXXXXXXXXX0000",
            customer_id="SYSTEM_CASH_OUT",
            transaction_type="WITHDRAWAL",
            amount=amt_cash,
            balance=0.0,
            atm_location=atm["location"],
            status=final_dispense
        )
    events.append(ScheduledEvent(t, "atm", "ATM Host Switch", "HIGH", corr_id, atm_builder2))

    # Step 5: SIEM Alert
    t += 1.0
    events.append(ScheduledEvent(t, "siem", "SIEM Alert Manager", "CRITICAL", corr_id, lambda ctx: SIEMPayload(
        correlation_id=corr_id,
        source_system="ATM EDR Agent",
        severity="CRITICAL",
        event_category="ATM_COMPROMISE",
        rule_name="ATM Local Malware Execution and Large Cash Out Activity"
    )))

    for ev in events:
        ev.context = context
    return events


# Map scenario functions
SCENARIOS_MAP = {
    "normal_banking": get_normal_banking_session,
    "normal_employee": get_normal_employee_session,
    "normal_atm": get_normal_atm_withdrawal,
    "normal_card": get_normal_card_transaction,
    
    "attack_credential_theft": get_attack_credential_theft,
    "attack_malware": get_attack_malware_infection,
    "attack_brute_force": get_attack_brute_force,
    "attack_insider": get_attack_insider_threat,
    "attack_ato": get_attack_account_takeover,
    "attack_card_fraud": get_attack_card_fraud,
    "attack_atm_jackpotting": get_attack_atm_jackpotting
}

def build_scenario_events(scenario_name: str, start_time: datetime) -> List[CommonEnvelope]:
    if scenario_name not in SCENARIOS_MAP:
        raise ValueError(f"Unknown scenario: {scenario_name}")
    
    scheduled = SCENARIOS_MAP[scenario_name]()
    built_events = []
    
    for item in scheduled:
        ev_time = start_time + timedelta(seconds=item.time_offset)
        ev = item.build(ev_time, item.context)
        built_events.append(ev)
        
    return built_events
