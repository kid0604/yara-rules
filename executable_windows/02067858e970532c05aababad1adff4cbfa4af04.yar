import "pe"

rule INDICATOR_KB_CERT_009272607cfc982b782a5d36c4b78f5e7b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "2514c615fe54d511555bc5b57909874e48a438918a54cea4a0b3fbc401afa127"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rada SP Z o o" and pe.signatures[i].serial=="00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b")
}
