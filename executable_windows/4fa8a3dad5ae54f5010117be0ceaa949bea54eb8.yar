import "pe"

rule VxTrivial25
{
	meta:
		author = "malware-lu"
		description = "Detects VxTrivial25 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }

	condition:
		$a0 at pe.entry_point
}
