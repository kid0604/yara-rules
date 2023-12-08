import "pe"

rule INDICATOR_KB_CERT_0d07705fa0e0c4827cc287cfcdec20c4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ba5f8c3d961d0df838361b4aa5ec600a70abe1e0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Binance Holdings Limited" and pe.signatures[i].serial=="0d:07:70:5f:a0:e0:c4:82:7c:c2:87:cf:cd:ec:20:c4")
}
