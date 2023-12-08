import "pe"

rule Upackv035alphaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack v0.35 alpha Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B F2 8B CA 03 4C 19 1C 03 54 1A 20 }

	condition:
		$a0
}
