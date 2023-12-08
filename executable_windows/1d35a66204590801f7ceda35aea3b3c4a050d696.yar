import "pe"

rule ASPackv102aAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.02a by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED 3E D9 43 ?? B8 38 [3] 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 [2] 75 15 FE 85 01 DE 43 ?? E8 1D [3] E8 79 02 [2] E8 12 03 [2] 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }

	condition:
		$a0 at pe.entry_point
}
