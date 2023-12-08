import "pe"

rule Mew10execoder10NorthfoxHCC
{
	meta:
		author = "malware-lu"
		description = "Detects the Mew10execoder10NorthfoxHCC malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 C0 E9 [2] FF FF 6A [5] 70 }

	condition:
		$a0 at pe.entry_point
}
