import "pe"

rule INDICATOR_KB_CERT_00ac307e5257bb814b818d3633b630326f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4d6a089ec4edcac438717c1d64a8be4ef925a9c6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Aqua Direct s.r.o." and pe.signatures[i].serial=="00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f")
}
