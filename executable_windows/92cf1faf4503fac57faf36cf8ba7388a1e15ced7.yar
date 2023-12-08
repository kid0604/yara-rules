import "pe"

rule ASPackv104bAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ASPack v1.04b Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED [4] B8 [4] 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D [2] 80 BD 08 9D }

	condition:
		$a0 at pe.entry_point
}
