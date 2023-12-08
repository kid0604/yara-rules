rule NewBomani
{
	meta:
		author = "rivitna"
		family = "ransomware.newbomani.windows"
		description = "NewBomani ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 7C ?? 7F 07 3D 00 00 ?0 0? 76 0? [4-12] 7C ?? 7F 07
                3D 00 00 40 06 76 ?? }
		$a2 = "expand 32-byte kexpand 16-byte k\\\x00" ascii
		$a3 = "{{IDENTIFER}}\x00" ascii
		$b1 = "EES401EP2\x00" ascii
		$b2 = { 91 01 00 08 01 00 08 00 08 00 06 00 85 00 65 00 70 00 0B 00
                0A 00 06 00 01 00 02 10 }
		$b3 = "EES587EP1\x00" ascii
		$b4 = { 4B 02 00 08 01 00 0A 00 0A 00 08 00 C4 00 9D 00 C0 00 0B 00
                0D 00 07 00 01 00 05 11 }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ( filesize <100000) and ((2 of ($a*)) or ((1 of ($a*)) and (1 of ($b*))))
}
