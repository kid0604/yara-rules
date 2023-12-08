import "pe"

rule INDICATOR_KB_CERT_00d4ef1ab6ab5d3cb35e4efb7984def7a2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "10d82c75a1846ebfb2a0d1abe9c01622bdfabf0a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REIGN BROS ApS" and pe.signatures[i].serial=="00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2")
}
