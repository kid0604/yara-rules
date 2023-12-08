import "pe"

rule INDICATOR_KB_CERT_025020668f51235e9ecfff8cf00da63e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "59f82837fa672a81841d8fa4d3ba290395c10200"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Knassar DK ApS" and pe.signatures[i].serial=="02:50:20:66:8f:51:23:5e:9e:cf:ff:8c:f0:0d:a6:3e")
}
