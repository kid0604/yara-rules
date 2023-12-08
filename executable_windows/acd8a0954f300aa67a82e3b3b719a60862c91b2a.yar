import "pe"

rule MEW10byNorthfox
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of MEW10 malware by Northfox"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 C0 E9 [2] FF FF ?? 1C [2] 40 }

	condition:
		$a0
}
