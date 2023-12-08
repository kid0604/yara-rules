import "pe"

rule PUNiSHERV15DemoFEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects PUNiSHERV15DemoFEUERRADER malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
