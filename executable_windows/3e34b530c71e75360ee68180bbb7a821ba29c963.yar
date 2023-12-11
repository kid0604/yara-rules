import "pe"

rule PKLITEv200c
{
	meta:
		author = "malware-lu"
		description = "Detects PKLITEv200c malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 B8 [2] BA [2] 3B C4 73 ?? 8B C4 2D [2] 25 [2] 8B F8 B9 [2] BE [2] FC }

	condition:
		$a0 at pe.entry_point
}
