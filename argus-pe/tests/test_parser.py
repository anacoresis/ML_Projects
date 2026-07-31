import os
import pytest
from argus.core.parser import PEParser


def test_invalid_file_handling():
    """Ensures non-PE files return safe zeroed schema without crashing."""
    parser = PEParser()
    result = parser._get_default_parser_output("non_existent.exe", is_valid_pe=False)
    assert result['is_valid_pe'] is False
    assert result['features']['max_section_entropy'] == 0.0
    assert result['features']['wx_section_count'] == 0.0


def test_parse_real_binary_if_present():
    """Tests parsing functionality against Kali system binaries if available."""
    nc_path = "/usr/share/windows-resources/binaries/nc.exe"
    if os.path.exists(nc_path):
        parser = PEParser()
        result = parser.parse(nc_path)
        
        assert result['is_valid_pe'] is True
        assert result['features']['num_sections'] > 0
        assert 'has_tls' in result['features']
        assert 'wx_section_count' in result['features']
        assert isinstance(result['metadata']['suspicious_apis_found'], list)
