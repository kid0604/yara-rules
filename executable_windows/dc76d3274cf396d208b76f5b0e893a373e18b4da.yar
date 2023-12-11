import "pe"

rule INDICATOR_KB_CERT_00e267fdbdc16f22e8185d35c437f84c87
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "cdf4a69402936ece82f3f9163e6cc648bcbb2680"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APOTHEKA, s.r.o." and pe.signatures[i].serial=="00:e2:67:fd:bd:c1:6f:22:e8:18:5d:35:c4:37:f8:4c:87")
}
