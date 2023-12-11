import "pe"

rule INDICATOR_KB_CERT_040f11f124a73bdecc41259845a8a773
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6f332f7e78cac4a6c35209fde248ef317f7a23e8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TrustPort" and pe.signatures[i].serial=="04:0f:11:f1:24:a7:3b:de:cc:41:25:98:45:a8:a7:73")
}
