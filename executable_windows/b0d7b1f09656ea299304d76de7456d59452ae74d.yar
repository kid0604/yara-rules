import "pe"

rule INDICATOR_KB_CERT_0d53690631dd186c56be9026eb931ae2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c5d1e46a40a8200587d067814adf0bbfa09780f5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "STA-R TOV" and pe.signatures[i].serial=="0d:53:69:06:31:dd:18:6c:56:be:90:26:eb:93:1a:e2")
}
