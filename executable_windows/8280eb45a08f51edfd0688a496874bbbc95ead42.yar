import "pe"

rule WebCopsEXELINKDataSecurity
{
	meta:
		author = "malware-lu"
		description = "Detects WebCops EXE Link Data Security"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72 }

	condition:
		$a0 at pe.entry_point
}
