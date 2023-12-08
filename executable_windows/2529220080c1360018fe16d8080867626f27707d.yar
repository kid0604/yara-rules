import "pe"

rule INDICATOR_KB_CERT_500d76b1b4bfaf4a131f027668fea2d3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "fa491e71d98c7e598e32628a6272a005df86b196"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FviSBJQX" and pe.signatures[i].serial=="50:0d:76:b1:b4:bf:af:4a:13:1f:02:76:68:fe:a2:d3")
}
