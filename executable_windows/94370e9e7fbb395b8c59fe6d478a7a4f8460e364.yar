rule INDICATOR_TOOL_PET_DefenderControl
{
	meta:
		author = "ditekSHen"
		description = "Detects Defender Control"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Windows Defender Control" wide
		$s2 = "www.sordum.org" wide ascii
		$s3 = "dControl" wide

	condition:
		uint16(0)==0x5a4d and 2 of them
}
