import "pe"

rule ASProtect13321RegisteredAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect 1.3.3.21 registered by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 01 [3] E8 01 00 00 00 C3 C3 }

	condition:
		$a0 at pe.entry_point
}
