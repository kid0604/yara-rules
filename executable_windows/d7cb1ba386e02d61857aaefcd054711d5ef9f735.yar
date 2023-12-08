import "pe"

rule UPXProtectorv10x_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects UPX Protector v1.0x alternate 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB EC [4] 8A 06 46 88 07 47 01 DB 75 07 }

	condition:
		$a0 at pe.entry_point
}
