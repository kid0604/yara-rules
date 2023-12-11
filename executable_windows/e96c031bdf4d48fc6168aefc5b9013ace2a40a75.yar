import "pe"

rule INDICATOR_KB_CERT_2abd2eef14d480dfea9ca9fdd823cf03
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "db3d9ccf11d8b0d4f33cf4dc93689fdd942f8fbe"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BE SOL d.o.o." and pe.signatures[i].serial=="2a:bd:2e:ef:14:d4:80:df:ea:9c:a9:fd:d8:23:cf:03")
}
