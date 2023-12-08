import "pe"

rule PEtitevxx
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PEtitevxx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}
