import "pe"

rule INDICATOR_KB_CERT_378d5543048e583a06a0819f25bd9e85
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "cf933a629598e5e192da2086e6110ad1974f8ec3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KITTY'S LTD" and pe.signatures[i].serial=="37:8d:55:43:04:8e:58:3a:06:a0:81:9f:25:bd:9e:85")
}
