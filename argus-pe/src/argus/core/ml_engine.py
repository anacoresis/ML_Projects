import os
import sys
import joblib
import pandas as pd
from typing import Dict, Any, Tuple


class MLEngine:
    """
    Handles Random Forest model loading, feature matrix alignment,
    and probability prediction for PE binaries.
    """

    EXPECTED_FEATURES = [
        'num_sections', 'size_of_code', 'size_of_image', 'size_of_init_data',
        'size_of_uninit_data', 'entry_point', 'file_characteristics', 'dll_characteristics',
        'max_section_entropy', 'mean_section_entropy', 'max_virtual_raw_ratio',
        'mean_virtual_raw_ratio', 'total_imports', 'imported_dlls',
        'suspicious_import_count', 'suspicious_api_ratio', 'has_debug_directory',
        'has_resources', 'has_tls', 'has_security_cert', 'has_rich_header', 'wx_section_count'
    ]

    def __init__(self, model_path: str = "models/argus_pe_model.pkl"):
        self.model_path = model_path
        self.model = self._load_model()

    def _load_model(self):
        """Loads trained Random Forest model from disk if present."""
        if os.path.exists(self.model_path):
            try:
                return joblib.load(self.model_path)
            except Exception:
                return None
        return None

    def predict(self, feature_dict: Dict[str, float]) -> Tuple[float, int]:
        """
        Accepts raw feature dictionary, aligns it against expected columns,
        and returns (malware_probability_percentage, predicted_class).
        """
        if self.model is None:
            # Fallback if model binary is missing
            return 0.0, 0

        # Construct single-row DataFrame matching trained feature order
        df = pd.DataFrame([feature_dict])
        
        # Ensure all expected columns exist
        for col in self.EXPECTED_FEATURES:
            if col not in df.columns:
                df[col] = 0.0

        df = df[self.EXPECTED_FEATURES]

        probabilities = self.model.predict_proba(df)[0]
        malware_prob = float(probabilities[1] * 100.0) if len(probabilities) > 1 else float(probabilities[0] * 100.0)
        prediction = int(self.model.predict(df)[0])

        return round(malware_prob, 2), prediction