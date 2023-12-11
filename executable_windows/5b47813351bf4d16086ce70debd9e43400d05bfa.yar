import "pe"

rule ASProtectSKE21xdllAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect SKE 2.1x DLL by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 [3] 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
