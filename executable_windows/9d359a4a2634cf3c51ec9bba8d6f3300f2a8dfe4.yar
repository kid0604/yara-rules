import "pe"

rule SoftProtectwwwsoftprotectbyru
{
	meta:
		author = "malware-lu"
		description = "Detects SoftProtect malware from www.softprotect.by"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 8D [5] C7 00 00 00 00 00 E8 [4] E8 [4] 8D [5] 50 E8 [4] 83 [5] 01 }

	condition:
		$a0 at pe.entry_point
}
