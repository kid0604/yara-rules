import "pe"

rule EPack14litefinalby6aHguT
{
	meta:
		author = "malware-lu"
		description = "Detects the EPack14litefinalby6aHguT malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 C0 8B C0 68 [4] 68 [4] E8 }

	condition:
		$a0 at pe.entry_point
}
