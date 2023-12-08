rule Unibovwood
{
	meta:
		author = "rivitna"
		family = "ransomware.unibovwood.windows"
		description = "Unibovwood/Alkhal ransomware Windows payload"
		severity = 10
		score = 100
		os = "windows"
		filetype = "executable"

	strings:
		$h0 = { CC 85 02 00 E8 [4] 89 45 ?? ( C7 C1 | B8 ) CE 87 02 00
                E8 [4] 89 45 ?? }

	condition:
		(( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550)) and ((1 of ($h*)))
}
