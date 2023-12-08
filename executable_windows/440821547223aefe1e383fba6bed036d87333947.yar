import "pe"

rule INDICATOR_KB_CERT_73f9819f3a1a49bac1e220d7f3e0009b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "bb04986cbd65f0994a544f197fbb26abf91228d9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jean Binquet" and pe.signatures[i].serial=="73:f9:81:9f:3a:1a:49:ba:c1:e2:20:d7:f3:e0:00:9b")
}
