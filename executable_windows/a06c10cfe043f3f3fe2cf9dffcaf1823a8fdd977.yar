import "pe"

rule VxFaxFreeTopo
{
	meta:
		author = "malware-lu"
		description = "Detects VxFaxFreeTopo malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FA 06 33 C0 8E C0 B8 [2] 26 [4] 50 8C C8 26 [4] 50 CC 58 9D 58 26 [4] 58 26 [4] 07 FB }

	condition:
		$a0 at pe.entry_point
}
