import "pe"

rule PackedwithPKLITEv150withCRCcheck1
{
	meta:
		author = "malware-lu"
		description = "Detects files packed with PKLITE v1.50 with CRC check"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1F B4 09 BA [2] CD 21 B8 [2] CD 21 }

	condition:
		$a0 at pe.entry_point
}
