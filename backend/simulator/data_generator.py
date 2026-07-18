import random
import uuid
from typing import Dict, Any, List

# Lists of realistic values for generating data
CITIES = ["Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Ahmedabad", "Chennai", "Kolkata", "Pune", "Jaipur", "Lucknow"]
COUNTRIES = ["India", "Germany", "United States", "United Kingdom", "France", "Italy", "Singapore", "United Arab Emirates", "Russia", "Netherlands"]

MERCHANTS = {
    "RETAIL": ["Amazon India", "Flipkart", "Reliance Retail", "D-Mart", "Myntra"],
    "FOOD": ["Zomato", "Swiggy", "Dominos India", "Starbucks Mumbai", "McDonalds Pune"],
    "TRAVEL": ["MakeMyTrip", "Indigo Airlines", "Uber India", "Ola Cabs", "IRCTC"],
    "GAMING": ["Steam Games", "PlayStation Network", "Epic Games Store", "Gaming Coins UK", "Supercell Coins"],
    "LUXURY": ["Gucci Milan", "Luxury Paris", "Rolex Dubai", "Louis Vuitton Delhi", "Tiffany Singapore"],
    "UTILITIES": ["Tata Power", "Airtel Pay", "Jio Recharge", "Adani Gas", "BESCOM"]
}

BANKS = [
    {"name": "State Bank of India", "ifsc_prefix": "SBIN0"},
    {"name": "HDFC Bank", "ifsc_prefix": "HDFC0"},
    {"name": "ICICI Bank", "ifsc_prefix": "ICIC0"},
    {"name": "Axis Bank", "ifsc_prefix": "UTIB0"},
    {"name": "Bank of Maharashtra", "ifsc_prefix": "MAHB0"}
]

PROCESSES = [
    {"name": "chrome.exe", "hash": "a4d3b6f2e1a3b5c6d7e8f901a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90123"},
    {"name": "outlook.exe", "hash": "3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a"},
    {"name": "slack.exe", "hash": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"},
    {"name": "teams.exe", "hash": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"},
    {"name": "explorer.exe", "hash": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"},
    {"name": "svchost.exe", "hash": "8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d"},
    {"name": "jackpot_helper.exe", "hash": "ffea7762bc1234567890abcdef1234567890abcdef1234567890abcdef1234"},
    {"name": "invoice.pdf.exe", "hash": "0a2b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b"},
    {"name": "cmd.exe", "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
]

THREAT_ACTORS = ["Wizard Spider", "Fancy Bear", "Lazarus Group", "LockBit Group", "Scattered Spider"]
MALWARE_FAMILIES = ["Cobalt Strike", "LockBit 3.0", "TrickBot", "Qakbot", "SystemSlasher", "JackpotMalware"]
ENCRYPTION_ALGS = ["Legacy RSA-2048 / AES-256", "Quantum-Safe Kyber-1024", "Legacy RSA-1024 / RC4", "AES-GCM-256"]

class EntityPool:
    def __init__(self):
        self.customers: List[Dict[str, Any]] = []
        self.employees: List[Dict[str, Any]] = []
        self.atms: List[Dict[str, Any]] = []
        self.merchants: List[Dict[str, Any]] = []
        self.threat_iocs: List[Dict[str, Any]] = []
        self._generate_pool()

    def _generate_ip(self, subnet_prefix: str) -> str:
        return f"{subnet_prefix}.{random.randint(2, 254)}"

    def _generate_pool(self):
        # 1. Generate 1000 Customers
        first_names = ["Aarav", "Aditya", "Amit", "Ananya", "Arjun", "Deepak", "Divya", "Ganesh", "Isha", "Karan", 
                       "Kavita", "Rahul", "Rohan", "Sanjay", "Shreya", "Siddharth", "Sunita", "Vikram", "Neha", "Pooja"]
        last_names = ["Sharma", "Verma", "Gupta", "Mehra", "Joshi", "Patel", "Shah", "Rao", "Nair", "Iyer", 
                      "Singh", "Kumar", "Choudhury", "Das", "Banerjee", "Reddy", "Pillai", "Mishra", "Joshi", "Kulkarni"]
        
        for i in range(1000):
            c_id = f"C_{1000 + i}"
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            city = random.choice(CITIES)
            branch = f"{city} Main Branch"
            
            # Map Customer to a typical IP subnet
            sub_prefix = f"{random.choice([103, 115, 122, 157])}.{random.randint(10, 240)}.{random.randint(10, 240)}"
            typical_ip = self._generate_ip(sub_prefix)
            
            dev_id = f"DEV_CUST_{1000 + i}"
            os_name = random.choice(["Android", "iOS", "Windows 11", "macOS Sonoma"])
            browser = "Safari Mobile" if os_name == "iOS" else ("Chrome Mobile" if os_name == "Android" else random.choice(["Chrome", "Firefox", "Edge"]))
            
            acc_num = f"ACC_{500000 + i}"
            upi = f"{name.lower().replace(' ', '')}{i}@mahabank"
            card = f"4532-XXXX-XXXX-{i:04d}"
            
            # Predefined beneficiaries (1-3 per customer)
            beneficiaries = []
            for b_idx in range(random.randint(1, 3)):
                b_bank = random.choice(BANKS)
                b_name = f"{random.choice(first_names)} {random.choice(last_names)}"
                beneficiaries.append({
                    "beneficiary_id": f"BEN_{uuid.uuid4().hex[:6].upper()}",
                    "name": b_name,
                    "account_number": f"{random.randint(100000000, 999999999)}",
                    "bank": b_bank["name"],
                    "ifsc": f"{b_bank['ifsc_prefix']}{random.randint(100000, 999999)}"
                })
            
            self.customers.append({
                "customer_id": c_id,
                "name": name,
                "city": city,
                "branch": branch,
                "typical_ip_subnet": sub_prefix,
                "typical_ip": typical_ip,
                "device_id": dev_id,
                "operating_system": os_name,
                "browser": browser,
                "account_number": acc_num,
                "upi_id": upi,
                "card_number": card,
                "beneficiaries": beneficiaries,
                "avg_spend": float(random.randint(100, 5000)),
                "balance": float(random.randint(50000, 2000000)),
                "overdraft_limit": float(random.choice([0.0, 0.0, 0.0, 50000.0, 100000.0]))
            })

        # 2. Generate 100 Employees
        emp_first = ["Rajesh", "Suresh", "Alok", "Priyanka", "Anil", "Meena", "Vijay", "Sunil", "Ritu", "Preeti"]
        emp_last = ["Deshmukh", "Kulkarni", "Patil", "Pawar", "Shinde", "Joshi", "Bhide", "Apte", "Kadam", "Gore"]
        roles = [
            {"title": "SOC Analyst", "auth": "MFA"},
            {"title": "Database Administrator", "auth": "MFA"},
            {"title": "Network Engineer", "auth": "MFA"},
            {"title": "Customer Service Representative", "auth": "PASSWORD"},
            {"title": "Branch Manager", "auth": "MFA"},
            {"title": "ATM Operations Technician", "auth": "PASSWORD"}
        ]
        
        for i in range(100):
            e_id = f"E_{2000 + i}"
            name = f"{random.choice(emp_first)} {random.choice(emp_last)}"
            username = f"{name.lower().split()[0]}.{name.lower().split()[1]}"
            role = random.choice(roles)
            
            # Corporate Subnet IP
            emp_ip = f"10.20.{random.choice([10, 20, 30, 45])}.{random.randint(2, 254)}"
            dev_id = f"DEV_EMP_{2000 + i}"
            
            self.employees.append({
                "employee_id": e_id,
                "name": name,
                "username": username,
                "role": role["title"],
                "auth_method": role["auth"],
                "typical_ip": emp_ip,
                "device_id": dev_id,
                "operating_system": "Windows 11" if random.random() > 0.1 else "macOS Sonoma"
            })

        # 3. Generate 20 ATMs
        locations = ["Mumbai Airport Terminal 2", "Pune Central Mall", "Delhi Metro Gate 4", "Bengaluru Tech Park", 
                     "Hyderabad Cyber City", "Ahmedabad Riverfront", "Chennai Beach Road", "Kolkata Park Street"]
        for i in range(20):
            self.atms.append({
                "atm_id": f"ATM_{100 + i:03d}",
                "location": random.choice(locations) + f" Zone {random.randint(1, 5)}",
                "cash_reserve": float(random.randint(100000, 1000000))
            })

        # 4. Generate 100 Merchants
        categories = list(MERCHANTS.keys())
        for i in range(100):
            cat = random.choice(categories)
            m_name = random.choice(MERCHANTS[cat])
            m_id = f"MERCH_{3000 + i}"
            self.merchants.append({
                "merchant_id": m_id,
                "name": m_name,
                "category": cat,
                "city": random.choice(CITIES),
                "country": "India" if cat != "LUXURY" else random.choice(COUNTRIES)
            })

        # 5. Generate 50 Threat Intel IOCs
        for i in range(50):
            ioc_type = random.choice(["IP", "Domain", "Hash"])
            val = ""
            if ioc_type == "IP":
                val = f"{random.randint(45, 198)}.{random.randint(10, 220)}.{random.randint(10, 220)}.{random.randint(10, 220)}"
            elif ioc_type == "Domain":
                val = f"malicious-domain-{i}.com"
            else:
                val = uuid.uuid4().hex + uuid.uuid4().hex
            
            actor = random.choice(THREAT_ACTORS)
            malware = random.choice(MALWARE_FAMILIES)
            
            self.threat_iocs.append({
                "ioc_id": f"IOC_{4000 + i}",
                "ioc_type": ioc_type,
                "ioc_value": val,
                "threat_actor": actor,
                "malware_family": malware,
                "confidence_score": round(random.uniform(0.65, 0.99), 2)
            })

    # Pick methods
    def get_random_customer(self) -> Dict[str, Any]:
        return random.choice(self.customers)

    def get_random_employee(self) -> Dict[str, Any]:
        return random.choice(self.employees)

    def get_random_atm(self) -> Dict[str, Any]:
        return random.choice(self.atms)

    def get_random_merchant(self) -> Dict[str, Any]:
        return random.choice(self.merchants)

    def get_random_ioc(self) -> Dict[str, Any]:
        return random.choice(self.threat_iocs)

    def get_merchant_by_category(self, category: str) -> Dict[str, Any]:
        matched = [m for m in self.merchants if m["category"] == category]
        return random.choice(matched) if matched else self.get_random_merchant()

pool = EntityPool()
