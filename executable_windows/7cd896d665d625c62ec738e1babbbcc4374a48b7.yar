import "pe"

rule INDICATOR_KB_CERT_21144343720267ba42f586105ff279de
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c56f79b4cc3a0e0894cd1e54facdf2db9d8ca62a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Varta Blue Dynamic" and pe.signatures[i].serial=="21:14:43:43:72:02:67:ba:42:f5:86:10:5f:f2:79:de")
}
