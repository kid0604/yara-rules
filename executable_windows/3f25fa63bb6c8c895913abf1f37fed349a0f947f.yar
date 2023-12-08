import "pe"

rule VxSlowload
{
	meta:
		author = "malware-lu"
		description = "Detects VxSlowload malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01 }

	condition:
		$a0 at pe.entry_point
}
