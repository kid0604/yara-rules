import "pe"

rule INDICATOR_KB_CERT_00c4188d6b70b4bd3b977b19abd04c1157
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "90fefd18c677d6e5ac6db969a7247e3eb0b018df"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PRESTO Co., s.r.o." and pe.signatures[i].serial=="00:c4:18:8d:6b:70:b4:bd:3b:97:7b:19:ab:d0:4c:11:57")
}
