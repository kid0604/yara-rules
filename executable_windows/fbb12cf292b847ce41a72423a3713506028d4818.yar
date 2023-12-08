import "pe"

rule INDICATOR_KB_CERT_7709d2df39e9a4f7db2f3cbc29b49743
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "04349ba0f4d74f46387cee8a13ee72ab875032b4396d6903a6e9e7f047426de8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Grina LLC" and pe.signatures[i].serial=="77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43")
}
