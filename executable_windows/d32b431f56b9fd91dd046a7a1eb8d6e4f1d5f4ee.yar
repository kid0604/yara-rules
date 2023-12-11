import "pe"

rule INDICATOR_KB_CERT_29f2093e925b7fe70a9ba7b909415251
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "f9fc647988e667ec92bdf1043ea1077da8f92ccc"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xD0\\x99\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xE4\\xB8\\x9D\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A" and pe.signatures[i].serial=="29:f2:09:3e:92:5b:7f:e7:0a:9b:a7:b9:09:41:52:51")
}
