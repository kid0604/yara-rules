import "pe"

rule GardianAngel10
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of GardianAngel10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 8C C8 8E D8 8E C0 FC BF [2] EB }

	condition:
		$a0 at pe.entry_point
}
