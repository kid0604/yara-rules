import "pe"

rule INDICATOR_KB_CERT_00d2caf7908aaebfa1a8f3e2136fece024
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "82baf9b781d458a29469e5370bc9752ebef10f3f8ea506ca6dd04ea5d5f70334"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FANATOR, OOO" and pe.signatures[i].serial=="00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24")
}
