import "pe"

rule VxVCL
{
	meta:
		author = "malware-lu"
		description = "Detects VxVCL malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89 }

	condition:
		$a0 at pe.entry_point
}
