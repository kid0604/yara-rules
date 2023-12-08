import "pe"

rule INDICATOR_KB_CERT_531549ed4d2d53fc7e1beb47c6b13d58
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a8e1f6e32e5342265dd3e28cc65060fb7221c529"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bdabfbdfbcbab" and pe.signatures[i].serial=="53:15:49:ed:4d:2d:53:fc:7e:1b:eb:47:c6:b1:3d:58")
}
