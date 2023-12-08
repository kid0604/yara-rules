import "pe"

rule INDICATOR_KB_CERT_0609b5aad2dfb81fbe6b75e4cfe372a6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a30013d7a055c98c4bfa097fe85110629ef13e67"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "vVBhgeghjdigSdWYSAdmy" and pe.signatures[i].serial=="06:09:b5:aa:d2:df:b8:1f:be:6b:75:e4:cf:e3:72:a6")
}
