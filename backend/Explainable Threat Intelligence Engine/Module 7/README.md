# FALCON Module 7: Explainable Threat Intelligence Engine

FALCON Module 7 is an asynchronous Python FastAPI microservice responsible for converting the structured analytical results produced by Module 6 (`UnifiedRiskAssessment`) into a comprehensive, transparent, and fully traceable `ExplainableThreatReport` (ETR) consumed by Module 8.

It is designed as a **purely deterministic explainability and formatting layer** without performing any threat detection, risk score calculations, AI inference, or automated response.

---

## High-Level Architecture

```text
Receive UnifiedRiskAssessment (Module 6)
       ↓
Input / Reference Business Validation
       ↓
Metadata Generation
       ↓
Populate Internal Text Templates (Executive Summary, Narrative, Root Cause, etc.)
       ↓
Attach Referenced Audit Fields
       ↓
Return ExplainableThreatReport
```

---

## Installation & Setup

### Prerequisites
* Python 3.12 or higher

### Local Virtual Environment Setup
1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the FastAPI development server:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8007 --reload
   ```
4. Access the API documentation at: [http://127.0.0.1:8007/docs](http://127.0.0.1:8007/docs)

---

## API Summary

* **`POST /api/v1/explain`**: Receives a `UnifiedRiskAssessment` object containing exactly the 9 official architecture-defined sections:
  1. **Assessment Information** (`assessment_information`)
  2. **Context Evaluation** (`context_evaluation`)
  3. **Risk Signal Aggregation** (`risk_signal_aggregation`)
  4. **Context-Aware Risk Score** (`context_aware_risk_score`)
  5. **Incident Classification** (`incident_classification`)
  6. **Confidence Assessment** (`confidence_assessment`)
  7. **Prioritization Decision** (`prioritization_decision`)
  8. **Response Priority** (`response_priority`)
  9. **Referenced Domain AI Assessment** (`referenced_domain_ai_assessment`)
  
  Returns the structured `ExplainableThreatReport` response.
* **`GET /health`**: Returns status availability information for deployment checks.

---

## Testing

Run the automated test suite using `pytest`:
```bash
pytest -v
```
