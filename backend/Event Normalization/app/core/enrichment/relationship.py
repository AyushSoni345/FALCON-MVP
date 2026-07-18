import logging
from typing import Dict, Any, List
from app.core.enrichment.base import BaseEnricher
from app.logging_config import log_pipeline

class RelationshipContextEngine(BaseEnricher):
    """
    Constructs deterministic, stable relationship keys and entity chains
    enabling Module 3 to perform instant graph-edge construction.
    """

    def enrich(self, event: Dict[str, Any]) -> Dict[str, Any]:
        rc = event.get("relationship_context", {})
        ident = event.get("identity_context", {})
        asset = event.get("asset_context", {})
        txn = event.get("financial_context", {})
        sec = event.get("security_context", {})
        info = event.get("event_information", {})

        event_uuid = info.get("event_uuid")
        corr_id = info.get("correlation_id")

        log_pipeline(
            logging.DEBUG,
            "Compiling entity relationship mappings and chains.",
            "relationship_context",
            "started",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        cust_id = ident.get("customer_id")
        emp_id = ident.get("employee_id")
        sess_id = ident.get("session_id")
        dev_id = ident.get("device_id")
        end_id = ident.get("endpoint_id")
        benef_id = ident.get("beneficiary_id") or txn.get("beneficiary_id")
        txn_id = txn.get("transaction_id")
        acct_num = ident.get("account_number")
        ip = ident.get("ip_address")
        proc_hash = sec.get("process_hash")

        rc.update({
            "customer_id": cust_id,
            "employee_id": emp_id,
            "session_id": sess_id,
            "device_id": dev_id,
            "endpoint_id": end_id,
            "beneficiary_id": benef_id,
            "transaction_id": txn_id
        })

        rel_keys = {}
        if cust_id and acct_num:
            rel_keys["customer_account"] = f"{cust_id}:::{acct_num}"
        if cust_id and sess_id:
            rel_keys["customer_session"] = f"{cust_id}:::{sess_id}"
        if dev_id and sess_id:
            rel_keys["device_session"] = f"{dev_id}:::{sess_id}"
        if txn_id and benef_id:
            rel_keys["transaction_beneficiary"] = f"{txn_id}:::{benef_id}"
        if end_id and proc_hash:
            rel_keys["endpoint_process"] = f"{end_id}:::{proc_hash}"
        if acct_num and benef_id:
            rel_keys["account_beneficiary"] = f"{acct_num}:::{benef_id}"

        rc["relationship_keys"] = rel_keys

        ident_chain = []
        if cust_id:
            ident_chain.append(f"customer:{cust_id}")
        if emp_id:
            ident_chain.append(f"employee:{emp_id}")
        if ident.get("username"):
            ident_chain.append(f"user:{ident.get('username')}")
        if ip:
            ident_chain.append(f"ip:{ip}")
        rc["identity_chain"] = ident_chain

        asset_chain = []
        if dev_id:
            asset_chain.append(f"device:{dev_id}")
        if end_id:
            asset_chain.append(f"endpoint:{end_id}")
        if asset.get("atm_id"):
            asset_chain.append(f"atm:{asset.get('atm_id')}")
        if asset.get("server_id"):
            asset_chain.append(f"server:{asset.get('server_id')}")
        rc["asset_chain"] = asset_chain

        txn_chain = []
        if acct_num:
            txn_chain.append(f"account:{acct_num}")
        if txn_id:
            txn_chain.append(f"transaction:{txn_id}")
        if benef_id:
            txn_chain.append(f"beneficiary:{benef_id}")
        rc["transaction_chain"] = txn_chain

        event["relationship_context"] = rc
        
        log_pipeline(
            logging.DEBUG,
            f"Relationship context generated: {len(rel_keys)} keys, {len(ident_chain)} identity chains",
            "relationship_context",
            "success",
            event_uuid=event_uuid,
            correlation_id=corr_id
        )

        return event
