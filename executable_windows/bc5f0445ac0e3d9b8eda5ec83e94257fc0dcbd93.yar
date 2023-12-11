rule MassLogger_alt_1
{
	meta:
		author = "kevoreilly"
		description = "MassLogger"
		cape_type = "MassLogger Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$name = "MassLogger"
		$fody = "Costura"

	condition:
		uint16(0)==0x5A4D and 2 of them
}
