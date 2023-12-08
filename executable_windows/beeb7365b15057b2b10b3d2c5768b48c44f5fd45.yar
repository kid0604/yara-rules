import "pe"

rule FSGv110EngbartxtWatcomCCEXE
{
	meta:
		author = "malware-lu"
		description = "Detects the FSG v1.10 Engbart text Watcom C/C++ executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 CD 20 03 ?? 8D ?? 80 [2] 00 [9] EB 02 }

	condition:
		$a0 at pe.entry_point
}
