import "pe"

rule INDICATOR_KB_CERT_00fa3dcac19b884b44ef4f81541184d6b0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "6557117e37296d7fdcac23f20b57e3d52cabdb8e5aa24d3b78536379d57845be"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unicom Ltd" and pe.signatures[i].serial=="00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0")
}
