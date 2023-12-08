import "pe"

rule INDICATOR_KB_CERT_0a5b4f67ad8b22afc2debe6ce5f8f679
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1213865af7ddac1568830748dbdda21498dfb0ba"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Farad LLC" and pe.signatures[i].serial=="0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79")
}
