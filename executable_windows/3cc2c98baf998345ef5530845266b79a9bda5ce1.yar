import "pe"

rule INDICATOR_KB_CERT_fcb3d3519e66e5b6d90b8b595f558e81
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8bf6e51dfe209a2ca87da4c6b61d1e9a92e336e1a83372d7a568132af3ad0196"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pegasun" and pe.signatures[i].serial=="fc:b3:d3:51:9e:66:e5:b6:d9:0b:8b:59:5f:55:8e:81")
}
