import "pe"

rule INDICATOR_KB_CERT_00945aaac27e7d6d810c0a542bedd562a4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "de7794505df4aeb1253500617e812f462592e163"
		hash1 = "df3dabd031184b67bab7043baaae17061c21939d725e751c0a6f6b7867d0cf34"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DYNAMX BUSINESS GROUP LTD." and (pe.signatures[i].serial=="94:5a:aa:c2:7e:7d:6d:81:0c:0a:54:2b:ed:d5:62:a4" or pe.signatures[i].serial=="00:94:5a:aa:c2:7e:7d:6d:81:0c:0a:54:2b:ed:d5:62:a4"))
}
