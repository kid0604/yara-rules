import "pe"

rule VBOXv42MTE
{
	meta:
		author = "malware-lu"
		description = "Detects VBOXv42MTE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }

	condition:
		$a0 at pe.entry_point
}
