import "pe"

rule INDICATOR_KB_CERT_3fd3661533eef209153c9afec3ba4d8a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "20ddd23f53e1ac49926335ec3e685a515ab49252"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SFB Regnskabsservice ApS" and pe.signatures[i].serial=="3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a")
}
