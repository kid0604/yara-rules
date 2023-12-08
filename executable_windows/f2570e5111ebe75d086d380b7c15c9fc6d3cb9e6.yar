import "pe"

rule INDICATOR_KB_CERT_28b691272719b1ee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5dcbc94a2fdcc151afa8c55f24d0d5124d3b6134"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2021945 Ontario Inc." and pe.signatures[i].serial=="28:b6:91:27:27:19:b1:ee")
}
