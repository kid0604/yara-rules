import "pe"

rule CopyControlv303
{
	meta:
		author = "malware-lu"
		description = "Detects the CopyControlv303 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }

	condition:
		$a0 at pe.entry_point
}
