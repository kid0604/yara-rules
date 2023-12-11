import "pe"

rule PKTINYv10withTINYPROGv38
{
	meta:
		author = "malware-lu"
		description = "Detects PKTINYv10 with TINYPROGv38"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2E C6 06 [3] 2E C6 06 [3] 2E C6 06 [3] E9 [2] E8 [2] 83 }

	condition:
		$a0 at pe.entry_point
}
