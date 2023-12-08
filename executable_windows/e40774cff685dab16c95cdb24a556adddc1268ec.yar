import "pe"

rule UPXProtectorv10x2
{
	meta:
		author = "malware-lu"
		description = "Detects UPX Protector v1.0x2"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB [5] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }

	condition:
		$a0
}
