import "pe"

rule IonicWindSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of IonicWindSoftware malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9B DB E3 9B DB E2 D9 2D 00 [2] 00 55 89 E5 E8 }

	condition:
		$a0 at pe.entry_point
}
