import "pe"

rule INDICATOR_KB_CERT_00c88af896b6452241fe00e3aaec11b1f8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9ce1cbf5be77265af2a22e28f8930c2ac5641e12"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TeamViewer Germany GmbH" and pe.signatures[i].serial=="00:c8:8a:f8:96:b6:45:22:41:fe:00:e3:aa:ec:11:b1:f8")
}
