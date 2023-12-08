import "pe"

rule VxBackfont900
{
	meta:
		author = "malware-lu"
		description = "Detects VxBackfont900 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] B4 30 CD 21 3C 03 [2] B8 [2] BA [2] CD 21 81 FA [4] BA [2] 8C C0 48 8E C0 8E D8 80 [3] 5A [2] 03 [3] 40 8E D8 80 [3] 5A [2] 83 }

	condition:
		$a0 at pe.entry_point
}
