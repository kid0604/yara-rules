import "pe"

rule INDICATOR_KB_CERT_3c5fc5d02273f297404f7b9306e447bb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3fa4a6efd5e443627e9e32e6effe04c991f4fe8f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Wirpool Soft" and pe.signatures[i].serial=="3c:5f:c5:d0:22:73:f2:97:40:4f:7b:93:06:e4:47:bb")
}
