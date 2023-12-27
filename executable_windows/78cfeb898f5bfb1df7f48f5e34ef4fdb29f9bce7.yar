rule AgentTeslaXor
{
	meta:
		author = "kevoreilly"
		description = "AgentTesla xor-based config decoding"
		cape_type = "AgentTesla Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}

	condition:
		uint16(0)==0x5A4D and any of them
}
