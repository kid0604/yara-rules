rule malware_sakula_xorloop
{
	meta:
		description = "XOR loops from Sakula malware"
		author = "David Cannings"
		md5 = "fc6497fe708dbda9355139721b6181e7"
		date = "2016-06-13"
		modified = "2023-01-27"
		os = "windows"
		filetype = "executable"

	strings:
		$opcodes_decode_loop01 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }
		$opcodes_decode_loop02 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }

	condition:
		uint16(0)==0x5A4D and any of ($opcodes*)
}
