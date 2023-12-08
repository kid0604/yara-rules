import "pe"

rule INDICATOR_KB_CERT_4f407eb50803845cc43937823e1344c0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "0c1ffe7df27537a3dccbde6f7a49e38c4971e852"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and pe.signatures[i].serial=="4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0")
}
