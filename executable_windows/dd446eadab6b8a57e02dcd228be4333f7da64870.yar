import "pe"

rule ASPackv103bAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.03b by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }

	condition:
		$a0 at pe.entry_point
}
