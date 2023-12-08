import "pe"

rule INDICATOR_KB_CERT_2dcd0699da08915dde6d044cb474157c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "13bf3156e66a57d413455973866102b0a1f6d45a1e6de050ca9dcf16ecafb4e2"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VENTE DE TOUT" and pe.signatures[i].serial=="2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c")
}
