import "pe"

rule FACRYPTv10
{
	meta:
		author = "malware-lu"
		description = "Detects FACRYPTv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B9 [2] B3 ?? 33 D2 BE [2] 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3 }

	condition:
		$a0 at pe.entry_point
}
