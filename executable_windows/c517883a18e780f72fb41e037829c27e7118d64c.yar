import "pe"

rule ExeLockv100
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ExeLockv100 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 8C C8 8E C0 BE [2] 26 [2] 34 ?? 26 [2] 46 81 [3] 75 ?? 40 B3 ?? B3 ?? F3 }

	condition:
		$a0 at pe.entry_point
}
