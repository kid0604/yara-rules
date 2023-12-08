rule ZeusPanda
{
	meta:
		author = "kevoreilly"
		description = "ZeusPanda Payload"
		cape_type = "ZeusPanda Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$code1 = {8B 01 57 55 55 55 55 55 55 53 51 FF 50 0C 85 C0 78 E? 55 55 6A 03 6A 03 55 55 6A 0A FF 37}
		$code2 = {8D 85 B0 FD FF FF 50 68 ?? ?? ?? ?? 8D 85 90 FA FF FF 68 0E 01 00 00 50 E8 ?? ?? ?? ?? 83 C4 10 83 F8 FF 7E ?? 68 04 01 00 00 8D 85 B0 FD FF FF}

	condition:
		uint16(0)==0x5A4D and all of them
}
