import "pe"

rule ASProtectv12AlexeySolodovnikovh1
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.2 by Alexey Solodovnikov"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 [3] 00 }

	condition:
		$a0
}
