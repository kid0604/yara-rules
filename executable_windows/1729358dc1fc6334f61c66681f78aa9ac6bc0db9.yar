import "pe"

rule INDICATOR_KB_CERT_84c3a47b739f1835d35b755d1e6741b5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8057f20f9f385858416ec3c0bd77394eff595b69"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bddbdcfabededdeadbefed" and pe.signatures[i].serial=="84:c3:a4:7b:73:9f:18:35:d3:5b:75:5d:1e:67:41:b5")
}
