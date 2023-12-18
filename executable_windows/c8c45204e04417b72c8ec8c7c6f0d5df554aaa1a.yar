import "pe"

rule INDICATOR_KB_CERT_db95b22362d46a73c39e0ac924883c5b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "751a7e6c4dbe6e7ca633b91515c9f620bff6314ce09969a3af26d18945dc43b5"
		reason = "Smoke Loader"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPSLTD PLYMOUTH LTD" and pe.signatures[i].serial=="db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b")
}
