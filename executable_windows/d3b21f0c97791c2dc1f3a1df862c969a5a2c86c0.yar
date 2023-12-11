import "pe"

rule ASPackv107bDLLAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASPack v1.07b DLL by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D [6] B8 [4] 03 C5 }

	condition:
		$a0 at pe.entry_point
}
