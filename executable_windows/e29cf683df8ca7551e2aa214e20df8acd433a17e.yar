import "pe"

rule INDICATOR_KB_CERT_537aa4f1bae48f052c3e57c3e2e1ee61
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "15355505a242c44d6c36abab6267cc99219a931c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALPHA AME LIMITED LLP" and pe.signatures[i].serial=="53:7a:a4:f1:ba:e4:8f:05:2c:3e:57:c3:e2:e1:ee:61")
}
