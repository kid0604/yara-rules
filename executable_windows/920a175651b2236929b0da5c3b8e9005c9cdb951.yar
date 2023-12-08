import "pe"

rule Upackv036alphaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.36 alpha Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }

	condition:
		$a0
}
