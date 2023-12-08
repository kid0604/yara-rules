import "pe"

rule INDICATOR_KB_CERT_6b6739e55f3f25b147c4a6767de41f57
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "07a09d3d3c05918519d6f357fe7eed5e1d529f22"
		hash = "da0921c1e416b3734272dfa619f88c8cd32e9816cdcbeeb81d9e2b2e8a95af4c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Avast Antivirus SEC" and pe.signatures[i].serial=="6b:67:39:e5:5f:3f:25:b1:47:c4:a6:76:7d:e4:1f:57")
}
