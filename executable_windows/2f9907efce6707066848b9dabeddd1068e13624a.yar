import "pe"

rule PECrc32088ZhouJinYu
{
	meta:
		author = "malware-lu"
		description = "Detects the PECrc32088ZhouJinYu malware based on its entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
