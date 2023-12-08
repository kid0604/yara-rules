import "pe"

rule VxNecropolis1963
{
	meta:
		author = "malware-lu"
		description = "Detects VxNecropolis1963 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 30 CD 21 3C 03 [2] B8 00 12 CD 2F 3C FF B8 [4] B4 4A BB 40 01 CD 21 [2] FA 0E 17 BC [2] E8 [2] FB A1 [2] 0B C0 }

	condition:
		$a0 at pe.entry_point
}
