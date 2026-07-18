import sys
import os
import types

# Inject virtual module 'module4' to resolve absolute imports during tests
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if 'module4' not in sys.modules:
    module4 = types.ModuleType('module4')
    module4.__path__ = [project_root]
    sys.modules['module4'] = module4
