import "pe"

rule INDICATOR_KB_CERT_b1bbef3aba79ab2eae5b8015f26b34f8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "247a10fc20386f4f54b7451aecc2d97ec77567c5031028cc7f1b98f9191bee80"
		reason = "NW0rm"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIDZHITAL ART, OOO" and pe.signatures[i].serial=="b1:bb:ef:3a:ba:79:ab:2e:ae:5b:80:15:f2:6b:34:f8")
}
