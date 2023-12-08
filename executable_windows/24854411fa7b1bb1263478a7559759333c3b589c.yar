import "pe"

rule aPackv062
{
	meta:
		author = "malware-lu"
		description = "Detects aPackv062 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E 06 8C C8 8E D8 [3] 8E C0 50 BE [2] 33 FF FC B6 }

	condition:
		$a0 at pe.entry_point
}
