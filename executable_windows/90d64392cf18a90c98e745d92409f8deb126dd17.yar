import "pe"

rule INDICATOR_KB_CERT_00df683d46d8c3832489672cc4e82d3d5d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "8b63c5ea8d9e4797d77574f35d1c2fdff650511264b12ce2818c46b19929095b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Osatokio Oy" and pe.signatures[i].serial=="00:df:68:3d:46:d8:c3:83:24:89:67:2c:c4:e8:2d:3d:5d")
}
