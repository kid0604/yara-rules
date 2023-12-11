import "pe"

rule INDICATOR_KB_CERT_00d4f9fc08895654f8bde8d1cc26eff015
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f24af3a784c2316b42854c5853b53d9e556295f7"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "kfbdAfVnDMDc" and pe.signatures[i].serial=="00:d4:f9:fc:08:89:56:54:f8:bd:e8:d1:cc:26:ef:f0:15")
}
