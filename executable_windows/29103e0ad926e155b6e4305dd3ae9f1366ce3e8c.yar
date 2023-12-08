import "pe"

rule INDICATOR_KB_CERT_719ac44966d05762ef95245eefcf3046
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "57ecdfa48ed03a5a8177887090b3d1ffaf124846"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "jZQtQDMvyDRzWsoVFeitFmeNcWMtKauvidXSUrSEwqmi" and pe.signatures[i].serial=="71:9a:c4:49:66:d0:57:62:ef:95:24:5e:ef:cf:30:46")
}
