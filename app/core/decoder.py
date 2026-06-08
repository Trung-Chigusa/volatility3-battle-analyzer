"""Automatic encoding detection and decoding module"""
import base64
import binascii
import re
from typing import List, Dict, Optional, Tuple
from urllib.parse import unquote
from dataclasses import dataclass
from .models import StringMatch


class Decoder:
    """Detects and decodes encoded strings from memory"""
    
    # Patterns for different encodings
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    BASE32_PATTERN = re.compile(r'[A-Z2-7]{20,}={0,6}')
    HEX_PATTERN = re.compile(r'[0-9A-Fa-f]{20,}')
    URL_ENCODED_PATTERN = re.compile(r'%[0-9A-Fa-f]{2}')
    
    def __init__(self):
        self.decoded_strings: List[Dict] = []
    
    def detect_and_decode(self, text: str) -> List[Dict[str, any]]:
        """Detect encoded strings in text and decode them
        
        Returns list of decoded results with metadata
        """
        results = []
        
        # Base64 detection and decoding
        base64_matches = self.BASE64_PATTERN.finditer(text)
        for match in base64_matches:
            encoded = match.group(0)
            try:
                # Try to decode
                decoded = base64.b64decode(encoded + '==')  # Add padding if needed
                decoded_str = decoded.decode('utf-8', errors='ignore')
                
                # Check if it's actually valid base64 and produces readable text
                if len(decoded_str) > 3 and self._is_readable(decoded_str):
                    results.append({
                        'original': encoded,
                        'decoded': decoded_str,
                        'encoding': 'base64',
                        'offset': match.start(),
                        'length': len(encoded),
                        'confidence': self._calculate_confidence(decoded_str)
                    })
            except Exception:
                pass
        
        # Base32 detection and decoding
        base32_matches = self.BASE32_PATTERN.finditer(text)
        for match in base32_matches:
            encoded = match.group(0)
            try:
                decoded = base64.b32decode(encoded + '======')  # Add padding
                decoded_str = decoded.decode('utf-8', errors='ignore')
                
                if len(decoded_str) > 3 and self._is_readable(decoded_str):
                    results.append({
                        'original': encoded,
                        'decoded': decoded_str,
                        'encoding': 'base32',
                        'offset': match.start(),
                        'length': len(encoded),
                        'confidence': self._calculate_confidence(decoded_str)
                    })
            except Exception:
                pass
        
        # Hex detection and decoding
        hex_matches = self.HEX_PATTERN.finditer(text)
        for match in hex_matches:
            encoded = match.group(0)
            # Only process if length is even (valid hex)
            if len(encoded) % 2 == 0:
                try:
                    decoded = binascii.unhexlify(encoded)
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    
                    if len(decoded_str) > 3 and self._is_readable(decoded_str):
                        results.append({
                            'original': encoded,
                            'decoded': decoded_str,
                            'encoding': 'hex',
                            'offset': match.start(),
                            'length': len(encoded),
                            'confidence': self._calculate_confidence(decoded_str)
                        })
                except Exception:
                    pass
        
        # URL encoding detection
        url_matches = self.URL_ENCODED_PATTERN.findall(text)
        if len(url_matches) > 5:  # If significant URL encoding found
            try:
                decoded_str = unquote(text)
                if decoded_str != text and self._is_readable(decoded_str):
                    results.append({
                        'original': text[:100],  # Truncate for display
                        'decoded': decoded_str[:200],
                        'encoding': 'url',
                        'offset': 0,
                        'length': len(text),
                        'confidence': self._calculate_confidence(decoded_str)
                    })
            except Exception:
                pass
        
        return results
    
    def _is_readable(self, text: str) -> bool:
        """Check if decoded text is readable (contains mostly printable characters)"""
        if not text:
            return False
        
        printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
        ratio = printable_count / len(text) if len(text) > 0 else 0
        
        # At least 70% should be printable
        return ratio >= 0.7
    
    def _calculate_confidence(self, text: str) -> float:
        """Calculate confidence score for decoded text (0.0 to 1.0)"""
        if not text:
            return 0.0
        
        score = 0.0
        
        # Check for common readable patterns
        if any(keyword in text.lower() for keyword in ['http', 'www', 'cmd', 'exe', 'dll', 'reg']):
            score += 0.3
        
        # Check for ASCII printable ratio
        printable_ratio = sum(1 for c in text if c.isprintable() or c.isspace()) / len(text)
        score += printable_ratio * 0.5
        
        # Check for common file paths
        if any(path_indicator in text for path_indicator in ['\\', '/', ':', '.exe', '.dll', '.txt']):
            score += 0.2
        
        return min(score, 1.0)
    
    def decode_string_match(self, string_match: StringMatch) -> List[Dict]:
        """Decode a string match and return decoded results"""
        results = self.detect_and_decode(string_match.match)
        
        # Add metadata about source
        for result in results:
            result['source_pid'] = string_match.pid
            result['source_process'] = string_match.process_name
            result['source_offset'] = string_match.offset
            result['source_region'] = string_match.region
        
        return results
    
    def decode_from_strings(self, strings: List[str], source_info: Optional[Dict] = None) -> List[Dict]:
        """Decode from a list of strings"""
        all_results = []
        
        for i, text in enumerate(strings):
            results = self.detect_and_decode(text)
            for result in results:
                if source_info:
                    result.update(source_info)
                result['string_index'] = i
                all_results.append(result)
        
        # Remove duplicates (same decoded content)
        seen = set()
        unique_results = []
        for result in all_results:
            key = (result['decoded'][:50], result['encoding'])
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results


@dataclass
class DecodedString:
    """Represents a decoded string with metadata"""
    original: str
    decoded: str
    encoding: str
    confidence: float
    source_pid: Optional[int] = None
    source_process: Optional[str] = None
    source_offset: Optional[int] = None
    source_region: Optional[str] = None
    location: Optional[str] = None  # Where it was found (process, file, etc.)

