rule M_APT_VIRTUALPITA_4
{
	meta:
		author = "Mandiant"
		md5 = "fe34b7c071d96dac498b72a4a07cb246"
		description = "Finds opcodes from 401f1c to 401f4f in fe34b7c071d96dac498b72a4a07cb246 to decode text with multiple XORs"
		os = "windows"
		filetype = "executable"

	strings:
		$x = {4? 8b 4? ?? 4? 83 c1 30 4? 8b 4? ?? 4? 8b 10 8b 4? ?? 4? 98 4? 8b 04 ?? ?? ?? ?? ?? 4? 31 c2 4? 8b 4? ?? 4? 83 c0 28 4? 8b 00 4? c1 e8 10 0f b6 c0 4? 98 4? 8b 04}

	condition:
		uint32(0)==0x464c457f and all of them
}
