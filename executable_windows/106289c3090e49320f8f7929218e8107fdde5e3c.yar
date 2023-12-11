import "pe"

rule INDICATOR_KB_CERT_3a727248e1940c5bf91a466b29c3b9cd
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "eeeb3a616bb50138f84fc0561d883b47ac1d3d3d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "\\xE5\\x90\\x89\\xE5\\x90\\x89\\xD0\\x98\\xE5\\x90\\x89\\xD0\\x98\\xE4\\xB8\\x9D\\xE4\\xB8\\x9D" and pe.signatures[i].serial=="3a:72:72:48:e1:94:0c:5b:f9:1a:46:6b:29:c3:b9:cd")
}
