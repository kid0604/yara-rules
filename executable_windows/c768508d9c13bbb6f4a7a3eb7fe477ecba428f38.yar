import "pe"

rule INDICATOR_KB_CERT_781ec65c3e38392d4c2f9e7f55f5c424
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5d20e8f899c7e48a0269c2b504607632ba833e40"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Facacafbfddbdbfad" and pe.signatures[i].serial=="78:1e:c6:5c:3e:38:39:2d:4c:2f:9e:7f:55:f5:c4:24")
}
