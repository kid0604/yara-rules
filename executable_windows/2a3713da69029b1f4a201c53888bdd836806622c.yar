import "pe"

rule VxNumberOne
{
	meta:
		author = "malware-lu"
		description = "Detects VxNumberOne malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F9 07 3C 53 6D 69 6C 65 3E E8 }

	condition:
		$a0 at pe.entry_point
}
