import "pe"

rule INDICATOR_KB_CERT_2d8cfcf04209dc7f771d8d18e462c35a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a9c61e299634ba01e269239de322fb85e2da006b"
		hash1 = "af27173ed576215bb06dab3a1526992ee1f8bd358a92d63ad0cfbc0325c70acf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AA PLUS INVEST d.o.o." and pe.signatures[i].serial=="2d:8c:fc:f0:42:09:dc:7f:77:1d:8d:18:e4:62:c3:5a")
}
