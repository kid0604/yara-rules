import "pe"

rule INDICATOR_KB_CERT_009bd81a9adaf71f1ff081c1f4a05d7fd7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "885b9f1306850a87598e5230fcae71282042b74e8a14cabb0a904c559b506acb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SMART TOYS AND GAMES" and pe.signatures[i].serial=="00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7")
}
