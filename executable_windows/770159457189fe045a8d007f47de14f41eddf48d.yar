import "pe"

rule INDICATOR_KB_CERT_009356e0361bcf983ab14276c332f814e7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "f8bc145719666175a2bb3fcc62e0f3b2deccb030"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE5\\x90\\x89\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE6\\x9D\\xB0\\xE5\\x90\\x89\\xE4\\xBC\\x8A" and pe.signatures[i].serial=="00:93:56:e0:36:1b:cf:98:3a:b1:42:76:c3:32:f8:14:e7")
}
