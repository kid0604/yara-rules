import "elf"

rule BlackMatter
{
	meta:
		author = "rivitna"
		family = "ransomware.blackmatter.windows"
		description = "BlackMatter ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { 80 C6 61              // add  dh, 61h
                80 EE 61              // sub  dh, 61h
                C1 CA 0D              // ror  edx, 0Dh
                03 D0 }
		$h1 = { 02 F1                 // add  dh, cl
                2A F1                 // sub  dh, cl
                B9 0D 00 00 00        // mov  ecx, 0Dh
                D3 CA                 // ror  edx, cl
                03 D0 }
		$h2 = { 3C 2B                 // cmp  al, 2Bh
                75 04                 // jnz  short L1
                B0 78                 // mov  al, 78h
                EB 0E                 // jnz  short L3
                                      // L1:
                3C 2F                 // cmp  al, 2Fh
                75 04                 // jnz  short L2
                B0 69                 // mov  al, 69h
                EB 06                 // jmp  short L3
                                      // L2:
                3C 3D                 // cmp  al, 3Dh
                75 02                 // jnz  short L3
                B0 7A }
		$h3 = { 33 C0                 // xor  eax, eax
                40                    // inc  eax
                40                    // inc  eax
                8D 0C C5 01 00 00 00  // lea  ecx, [eax*8+1]
                83 7D 0? 00           // cmp  [ebp+arg_0], 0
                75 04                 // jnz  short L1
                F7 D8                 // neg  eax
                EB 0? }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((1 of ($h*)))
}
