import "pe"

rule DCryptPrivate09bdrmist
{
	meta:
		author = "malware-lu"
		description = "Detects the DCryptPrivate09bdrmist malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B9 [3] 00 E8 00 00 00 00 58 68 [3] 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }

	condition:
		$a0 at pe.entry_point
}
