from app.templates.manager import ReportTemplateManager
from app.formatters.formatter import ReportFormatter

class BaseGenerator:
    """Base class for all report section generators."""
    def __init__(self, template_manager: ReportTemplateManager, formatter: ReportFormatter):
        self.templates = template_manager
        self.formatter = formatter
