rule PikaBot_alt_3
{
	meta:
		author = "kevoreilly"
		description = "Pikabot Payload"
		cape_type = "PikaBot Payload"
		packed = "89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9"
		os = "windows"
		filetype = "executable"

	strings:
		$decode = {29 D1 01 4B ?? 8D 0C 10 89 4B ?? 85 F6 74 02 89 16}
		$indirect = {31 C0 64 8B 0D C0 00 00 00 85 C9 74 01 40 50 8D 54 24 ?? E8 [4] A3 [4] 8B 25 [4] A1}
		$config = {C7 44 24 [3] 00 00 C7 44 24 [4] 00 89 [1-4] ?? E8 [4] 31 C0 C7 44 24 [3] 00 00 89 44 24 ?? C7 04 24 [4] E8}

	condition:
		uint16(0)==0x5A4D and 2 of them
}
