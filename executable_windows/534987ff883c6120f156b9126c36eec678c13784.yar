rule Remcos_alt_1
{
	meta:
		author = "kevoreilly"
		description = "Remcos Payload"
		cape_type = "Remcos Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$name = "Remcos" nocase
		$time = "%02i:%02i:%02i:%03i"
		$crypto1 = {81 E1 FF 00 00 80 79 ?? 4? 81 C9 00 FF FF FF 4? 8A ?4 8?}
		$crypto2 = {0F B6 [1-7] 8B 45 08 [0-2] 8D 34 07 8B 01 03 C2 8B CB 99 F7 F9 8A 84 95 ?? ?? FF FF 30 06 47 3B 7D 0C 72}

	condition:
		uint16(0)==0x5A4D and ($name) and ($time) and any of ($crypto*)
}
