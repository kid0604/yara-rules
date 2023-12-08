import "pe"

rule Upackv024v028AlphaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack v024-v028 AlphaDwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 88 01 40 00 AD [2] 95 AD 91 F3 A5 AD }

	condition:
		$a0 at pe.entry_point
}
