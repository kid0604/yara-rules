rule BumbleBee_alt_1
{
	meta:
		author = "enzo & kevoreilly"
		description = "BumbleBee Payload"
		cape_type = "BumbleBee Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$antivm1 = {84 C0 74 09 33 C9 FF [4] 00 CC 33 C9 E8 [3] 00 4? 8B C8 E8}
		$antivm2 = {84 C0 0F 85 [2] 00 00 33 C9 E8 [4] 48 8B C8 E8 [4] 48 8D 85}
		$antivm3 = {33 C9 E8 [4] 48 8B C8 E8 [4] 83 CA FF 48 8B 0D [4] FF 15}
		$antivm4 = {33 C9 E8 [4] 48 8B C8 E8 [4] 90 48 8B 05 [4] 48 85 C0 74}
		$str_ua = "bumblebee"
		$str_gate = "/gate"

	condition:
		uint16(0)==0x5A4D and ( any of ($antivm*) or all of ($str_*))
}
