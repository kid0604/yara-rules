import "pe"

rule INDICATOR_KB_CERT_0940fa9a4080f35052b2077333769c2f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "da154c058cd75ff478b248701799ea8c683dd7a5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROFF LAIN, OOO" and pe.signatures[i].serial=="09:40:fa:9a:40:80:f3:50:52:b2:07:73:33:76:9c:2f")
}
