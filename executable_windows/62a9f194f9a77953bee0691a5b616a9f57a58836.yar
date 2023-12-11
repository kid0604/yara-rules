rule Thanos_alt_1
{
	meta:
		author = "rivitna"
		family = "ransomware.thanos"
		description = "Thanos ransomware Windows"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { 02 03 20 20 CE 00 00 73 ?? 00 00 0A ( 0A | 2A ) }
		$h1 = { 28 ?? 00 00 0A 28 ?? 00 00 0A 73 ?? 00 00 0A 28 ?? 00 00
                0A 21 00 22 E2 33 0E 00 00 00 }
		$h2 = { 21 00 22 E2 33 0E 00 00 00 0A
                28 ?? ?? 00 0A 28 ?? 00 00 0A 73 ?? ?? 00 0A 28 ?? ?? 00 0A
                06 }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((1 of ($h*)))
}
