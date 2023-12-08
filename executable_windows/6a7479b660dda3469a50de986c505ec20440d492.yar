import "pe"

rule VxMTEnonencrypted
{
	meta:
		author = "malware-lu"
		description = "Detects non-encrypted VxMTEnonencrypted malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F7 D9 80 E1 FE 75 02 49 49 97 A3 [2] 03 C1 24 FE 75 02 48 }

	condition:
		$a0 at pe.entry_point
}
