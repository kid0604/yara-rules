import "pe"

rule Obsidiumv1111
{
	meta:
		author = "malware-lu"
		description = "Detects Obsidium v1.1.1 packer used in Windows executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 E7 1C 00 00 }

	condition:
		$a0 at pe.entry_point
}
