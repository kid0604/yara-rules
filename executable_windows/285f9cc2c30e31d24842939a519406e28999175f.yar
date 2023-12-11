import "pe"

rule INDICATOR_KB_CERT_55b5e1cf84a89c4e023399784b42a268
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "940345ed6266b67a768296ad49e51bbaa6ee8e97"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fbbdefaccbbcdc" and pe.signatures[i].serial=="55:b5:e1:cf:84:a8:9c:4e:02:33:99:78:4b:42:a2:68")
}
