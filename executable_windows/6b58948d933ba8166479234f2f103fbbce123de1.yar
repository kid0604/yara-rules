import "pe"

rule INDICATOR_KB_CERT_13039da3b2924b7a8b0a2ac4637c2efa
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ad9fa264674c152b2298533e41e098bcaa0345af"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Tekhnokom" and pe.signatures[i].serial=="13:03:9d:a3:b2:92:4b:7a:8b:0a:2a:c4:63:7c:2e:fa")
}
