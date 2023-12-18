import "pe"

rule INDICATOR_KB_CERT_623eae6a66d3a6ee80df9ccebe51181e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "21c4e9af43068d041e6aec84341ae89cabb9917792c4bc372eced059555bb845"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GAIN AI LTD" and pe.signatures[i].serial=="62:3e:ae:6a:66:d3:a6:ee:80:df:9c:ce:be:51:18:1e")
}
