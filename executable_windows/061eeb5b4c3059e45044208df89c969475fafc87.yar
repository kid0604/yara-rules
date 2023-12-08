import "pe"

rule XPack152164
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of XPack152164 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B EC FA 33 C0 8E D0 BC [2] 2E [4] 2E [4] EB }

	condition:
		$a0 at pe.entry_point
}
