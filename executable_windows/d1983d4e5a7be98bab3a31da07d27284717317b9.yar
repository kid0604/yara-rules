rule Beast_alt_1
{
	meta:
		author = "rivitna"
		family = "ransomware.beast"
		description = "Beast ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { 6A 00 56 68 ?? ?? 00 00 57 6A 19 68 AA 00 00 00 6A ??
                6A 0A 68 00 10 00 50 50 }
		$h1 = { 6A 00 56 68 ?? ?? 00 00 57 6A 19 68 AA 00 00 00
                68 ?? 00 00 00 6A 0A 68 00 10 00 50 50 }
		$h2 = { 81 BC 24 ?? 00 00 00 50 4B 06 06 75 6?
                81 BC 24 ?? 00 00 00 50 4B 06 07 75 5?
                81 BC 24 ?? 00 00 00 50 4B 05 06 75 }
		$h3 = { C7 44 24 ?? 17 10 14 06 }
		$h4 = { 40 04 19 08 C7 45 ?? 19 04 23 04 C7 45 ?? 3F 04 40 04
                C7 45 ?? 28 04 42 04 C7 45 ?? 43 08 22 04 }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((3 of ($h*)))
}
