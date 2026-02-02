"""
Payload Factory - Manages payload generation
"""

import hashlib
import json
from typing import Dict, List, Any

class PayloadFactory:
    def __init__(self):
        self.payload_cache = {}
    
    def generate_payload(self,
                        generator_type: str,
                        lhost: str,
                        lport: int,
                        payload_type: str,
                        output_format: str = "exe",
                        evasion_level: str = "intermediate",
                        **kwargs) -> Dict[str, Any]:
        """
        Generate payload with caching
        """
        # Create cache key
        cache_key_data = {
            "lhost": lhost,
            "lport": lport,
            "payload_type": payload_type,
            "format": output_format,
            "evasion": evasion_level,
            **kwargs
        }
        cache_key = hashlib.md5(json.dumps(cache_key_data, sort_keys=True).encode()).hexdigest()
        
        # Check cache
        if cache_key in self.payload_cache:
            return self.payload_cache[cache_key]
        
        # Import here to avoid circular imports
        from .meterpreter import MeterpreterGenerator
        
        # Create generator
        generator = MeterpreterGenerator(lhost, lport, payload_type)
        
        # Generate payload
        payload, metadata = generator.generate(
            output_format=output_format,
            arch=kwargs.get('arch', 'x64'),
            encoder=kwargs.get('encoder'),
            iterations=kwargs.get('iterations', 1)
        )
        
        # Prepare result
        result = {
            "payload": payload,
            "metadata": metadata,
            "cache_key": cache_key,
            "size": len(payload),
            "format": output_format
        }
        
        # Cache the result
        self.payload_cache[cache_key] = result
        
        return result
    
    def clear_cache(self):
        """Clear payload cache"""
        self.payload_cache.clear()
        return {"status": "cache_cleared", "items_removed": len(self.payload_cache)}
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return {
            "cached_payloads": len(self.payload_cache)
        }
