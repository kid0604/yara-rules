import "pe"

rule INDICATOR_KB_CERT_00c2fc83d458e653837fcfc132c9b03062
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "82294a7efa5208eb2344db420b9aeff317337a073c1a6b41b39dda549a94557e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Vertical" and pe.signatures[i].serial=="00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62")
}
