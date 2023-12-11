import "pe"

rule INDICATOR_KB_CERT_00b97f66bb221772dc07ef1d4bed8f6085
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "fb4efb3bfcef8e9a667c8657f2e3c8fb7436666e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "S-PRO d.o.o." and pe.signatures[i].serial=="00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85")
}
