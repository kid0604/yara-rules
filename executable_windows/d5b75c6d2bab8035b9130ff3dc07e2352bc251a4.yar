import "pe"

rule Petitevafterv14
{
	meta:
		author = "malware-lu"
		description = "Detects Petite variant 14"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 8D [5] 68 [4] 83 }

	condition:
		$a0 at pe.entry_point
}
