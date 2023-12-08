import "pe"

rule INDICATOR_KB_CERT_00a7e1dc5352c3852c5523030f57f2425c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "09232474b95fc2cfb07137e1ada82de63ffe6fcd"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pushka LLC" and pe.signatures[i].serial=="00:a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c")
}
