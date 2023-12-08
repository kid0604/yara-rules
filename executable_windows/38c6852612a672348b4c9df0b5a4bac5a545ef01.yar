rule Play_alt_1
{
	meta:
		author = "rivitna"
		family = "ransomware.play"
		description = "Play ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { 68 04 02 00 00 68 00 10 00 00 68 00 04 00 00 6A 00 E8 [4]
                83 C4 10 89 }
		$h1 = { 6A 04 68 00 10 00 00 68 00 FF 7F 00 6A 00 E8 [4]
                83 C4 10 8B }
		$h2 = { 6A 04 68 00 10 00 00 68 60 1C 01 00 6A 00 E8 [4]
                83 C4 10 89 }
		$h3 = { 6A 04 68 00 10 00 00 68 A0 5E 01 00 6A 00 E8 [4]
                83 C4 10 89 }
		$h4 = { 05 28 44 23 24 89 [4-8] 81 E9 89 35 14 7A 89 [6-12]
                05 4F 86 C8 61 89 }
		$h5 = { 6A 12 6B 85 [2] FF FF 12 05 [4] 50 6A 12 8D 8? [2] FF FF 5?
                E8 [4] 83 C4 10 }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((3 of ($h*)))
}
