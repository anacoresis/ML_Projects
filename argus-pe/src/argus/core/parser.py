import math
import os
from collections import Counter
from typing import Dict, Any, List
import pefile


class PEParser:
    """
    Advanced PE parser for extracting structural, mathematical, 
    and Windows Internals metadata from executable binaries.
    """

    # Win32 API monitoring catalog categorized by attacker capabilities
    SUSPICIOUS_APIS = {
        # Process Injection & Direct Memory Manipulation
        'virtualalloc', 'virtualalloc-ex', 'virtualprotect', 'virtualprotectex',
        'writeprocessmemory', 'readprocessmemory', 'createremotethread', 'ntwritevirtualmemory',
        'queueuserapc', 'setwindowshookexa', 'setwindowshookexw',
        
        # Dynamic API Loading & Process Spawning
        'loadlibrarya', 'loadlibraryw', 'loadlibraryexa', 'getprocaddress',
        'winexec', 'shellexecutea', 'shellexecutew', 'createprocessa', 'createprocessw',
        
        # Anti-Analysis & Anti-Debugging
        'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
        'outputdebugstringa', 'findwindowa', 'gettickcount',
        
        # Network Exfiltration & Persistence
        'httpsendrequesta', 'internetopena', 'urldownloadtofilea', 'regsetvalueexa'
    }

    # Windows PE Section Permission Characteristics Flags
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_WRITE   = 0x80000000
    IMAGE_SCN_MEM_READ    = 0x40000000

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculates byte Shannon Entropy H(X) in bits per byte [0.0 - 8.0].
        High entropy (> 7.0) indicates compression, packing, or encryption.
        """
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(float(entropy), 4)

    def parse(self, file_path: str) -> Dict[str, Any]:
        """
        Parses a target PE binary and returns a unified analysis payload
        containing feature vectors for ML models and structural metadata for heuristics.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Binary file not found: {file_path}")

        try:
            pe = pefile.PE(file_path, fast_load=False)
        except pefile.PEFormatError:
            # File is corrupt, truncated, or not a valid PE header
            return self._get_default_parser_output(file_path, is_valid_pe=False)

        # 1. PE Optional & File Header Attributes
        num_sections = len(pe.sections)
        size_of_code = float(pe.OPTIONAL_HEADER.SizeOfCode)
        size_of_image = float(pe.OPTIONAL_HEADER.SizeOfImage)
        size_of_init_data = float(pe.OPTIONAL_HEADER.SizeOfInitializedData)
        size_of_uninit_data = float(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
        entry_point = float(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        characteristics = float(pe.FILE_HEADER.Characteristics)
        dll_characteristics = float(pe.OPTIONAL_HEADER.DllCharacteristics)

        # 2. Section Traversals (Entropy, Size Ratios, W^X Memory Protection Checking)
        section_entropies: List[float] = []
        size_ratios: List[float] = []
        wx_section_count = 0

        for section in pe.sections:
            entropy = self.calculate_entropy(section.get_data())
            section_entropies.append(entropy)

            raw_s = float(section.SizeOfRawData)
            virt_s = float(section.Misc_VirtualSize)
            ratio = virt_s / (raw_s if raw_s > 0 else 1.0)
            size_ratios.append(ratio)

            # Evaluate W^X Bitwise Violation: Writable (0x80000000) AND Executable (0x20000000)
            flags = section.Characteristics
            is_writable = bool(flags & self.IMAGE_SCN_MEM_WRITE)
            is_executable = bool(flags & self.IMAGE_SCN_MEM_EXECUTE)
            if is_writable and is_executable:
                wx_section_count += 1

        max_entropy = max(section_entropies) if section_entropies else 0.0
        mean_entropy = sum(section_entropies) / len(section_entropies) if section_entropies else 0.0
        max_ratio = max(size_ratios) if size_ratios else 0.0
        mean_ratio = sum(size_ratios) / len(size_ratios) if size_ratios else 0.0

        # 3. Import Address Table (IAT) Parsing
        total_imports = 0
        suspicious_imports = 0
        imported_dll_count = 0
        suspicious_api_list: List[str] = []

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imported_dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    total_imports += 1
                    if imp.name:
                        name_str = imp.name.decode('utf-8', errors='ignore').lower()
                        if name_str in self.SUSPICIOUS_APIS:
                            suspicious_imports += 1
                            suspicious_api_list.append(name_str)

        suspicious_api_ratio = (suspicious_imports / total_imports) if total_imports > 0 else 0.0

        # 4. Windows Internals Directories Inspection
        has_tls = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0.0
        tls_callback_count = 0
        if has_tls and hasattr(pe.DIRECTORY_ENTRY_TLS, 'struct') and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            tls_callback_count = len(pe.DIRECTORY_ENTRY_TLS.callbacks) if hasattr(pe.DIRECTORY_ENTRY_TLS, 'callbacks') else 1

        has_security_cert = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 0.0
        has_debug = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0.0
        has_resources = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0.0
        has_exports = 1.0 if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0.0
        has_rich_header = 1.0 if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER else 0.0

        pe.close()

        # Construct Unified ARGUS Analysis Payload
        return {
            'file_path': file_path,
            'is_valid_pe': True,
            'features': {
                'num_sections': float(num_sections),
                'size_of_code': size_of_code,
                'size_of_image': size_of_image,
                'size_of_init_data': size_of_init_data,
                'size_of_uninit_data': size_of_uninit_data,
                'entry_point': entry_point,
                'file_characteristics': characteristics,
                'dll_characteristics': dll_characteristics,
                'max_section_entropy': round(max_entropy, 4),
                'mean_section_entropy': round(mean_entropy, 4),
                'max_virtual_raw_ratio': round(max_ratio, 4),
                'mean_virtual_raw_ratio': round(mean_ratio, 4),
                'total_imports': float(total_imports),
                'imported_dlls': float(imported_dll_count),
                'suspicious_import_count': float(suspicious_imports),
                'suspicious_api_ratio': round(float(suspicious_api_ratio), 4),
                'has_debug_directory': has_debug,
                'has_resources': has_resources,
                'has_tls': has_tls,
                'has_security_cert': has_security_cert,
                'has_rich_header': has_rich_header,
                'wx_section_count': float(wx_section_count)
            },
            'metadata': {
                'suspicious_apis_found': sorted(list(set(suspicious_api_list))),
                'tls_callback_count': tls_callback_count,
                'wx_section_count': wx_section_count,
                'has_exports': bool(has_exports)
            }
        }

    def _get_default_parser_output(self, file_path: str, is_valid_pe: bool = False) -> Dict[str, Any]:
        """Provides a safe, zeroed schema fallback for corrupted or non-PE files."""
        return {
            'file_path': file_path,
            'is_valid_pe': is_valid_pe,
            'features': {
                'num_sections': 0.0, 'size_of_code': 0.0, 'size_of_image': 0.0,
                'size_of_init_data': 0.0, 'size_of_uninit_data': 0.0, 'entry_point': 0.0,
                'file_characteristics': 0.0, 'dll_characteristics': 0.0,
                'max_section_entropy': 0.0, 'mean_section_entropy': 0.0,
                'max_virtual_raw_ratio': 0.0, 'mean_virtual_raw_ratio': 0.0,
                'total_imports': 0.0, 'imported_dlls': 0.0,
                'suspicious_import_count': 0.0, 'suspicious_api_ratio': 0.0,
                'has_debug_directory': 0.0, 'has_resources': 0.0,
                'has_tls': 0.0, 'has_security_cert': 0.0,
                'has_rich_header': 0.0, 'wx_section_count': 0.0
            },
            'metadata': {
                'suspicious_apis_found': [],
                'tls_callback_count': 0,
                'wx_section_count': 0,
                'has_exports': False
            }
        }