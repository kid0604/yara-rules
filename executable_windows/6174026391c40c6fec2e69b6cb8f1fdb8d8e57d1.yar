import "pe"

rule ASPackv1061bAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.06.1b by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }

	condition:
		$a0 at pe.entry_point
}
