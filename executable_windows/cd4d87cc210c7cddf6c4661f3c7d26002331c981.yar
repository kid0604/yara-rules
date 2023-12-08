import "pe"

rule nbuildv10soft
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of nbuildv10soft malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B9 [2] BB [2] C0 [2] 80 [2] 43 E2 }

	condition:
		$a0 at pe.entry_point
}
