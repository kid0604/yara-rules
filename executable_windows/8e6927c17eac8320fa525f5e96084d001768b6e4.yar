import "pe"

rule VxNovember17768
{
	meta:
		author = "malware-lu"
		description = "Detects VxNovember17768 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] 50 33 C0 8E D8 80 3E [3] 0E 1F [2] FC }

	condition:
		$a0 at pe.entry_point
}
