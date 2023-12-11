import "pe"

rule INDICATOR_KB_CERT_0092bc051f1811bb0b86727c36394f7849
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d1f9930521e172526a9f018471d4575d60d8ad8f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MISTO EKONOMSKE STORITVE, d.o.o." and pe.signatures[i].serial=="00:92:bc:05:1f:18:11:bb:0b:86:72:7c:36:39:4f:78:49")
}
