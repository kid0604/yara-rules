import "pe"

rule INDICATOR_KB_CERT_40e27b7404aa9b485f8a2fc0c8e53af3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ca468ff8403a8416042705e79dbc499a5ea9be85"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Southern Wall Systems, LLC" and pe.signatures[i].serial=="40:e2:7b:74:04:aa:9b:48:5f:8a:2f:c0:c8:e5:3a:f3")
}
