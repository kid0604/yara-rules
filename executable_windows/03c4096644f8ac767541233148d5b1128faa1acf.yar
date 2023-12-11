import "pe"

rule GamehouseMediaProtectorVersionUnknown
{
	meta:
		author = "malware-lu"
		description = "Detects Gamehouse Media Protector of unknown version"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] 6A 00 FF 15 [4] 50 FF 15 [3] 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
