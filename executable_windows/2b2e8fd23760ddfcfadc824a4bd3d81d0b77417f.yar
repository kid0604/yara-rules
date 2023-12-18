import "pe"

rule INDICATOR_KB_CERT_dfc1f1b0f205cc17ed7d216bb991f859
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b577362c1abcfb7d163b8702f23a6a3643c72ea0a3c8cf262092903a3110fa04"
		reason = "PrivateLoader"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Astori LLC" and pe.signatures[i].serial=="df:c1:f1:b0:f2:05:cc:17:ed:7d:21:6b:b9:91:f8:59")
}
