import "pe"

rule aPackv098m
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of aPackv098m malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E 06 8C C8 8E D8 05 [2] 8E C0 50 BE [2] 33 FF FC B2 ?? BD [2] 33 C9 50 A4 BB [2] 3B F3 76 }

	condition:
		$a0
}
