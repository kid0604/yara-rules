import "pe"

rule NsPack14Liuxingping
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the NsPack14Liuxingping malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 [2] 40 00 2D [2] 40 00 }

	condition:
		$a0 at pe.entry_point
}
