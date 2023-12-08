import "pe"

rule VxCIHVersion12TTITWIN95CIH
{
	meta:
		author = "malware-lu"
		description = "Detects VxCIHVersion12TTITWIN95CIH malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8D [3] 33 DB 64 87 03 E8 [4] 5B 8D }

	condition:
		$a0 at pe.entry_point
}
