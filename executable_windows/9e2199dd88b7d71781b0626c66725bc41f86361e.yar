import "pe"

rule INDICATOR_KB_CERT_8538a6c5018f50fc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d42519dac24abc5c1ebfc6e0da0fd2e7cfb9db50c0598948c6630fdc132c7f94"
		reason = "Malware"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Trading Technologies International, Inc." and pe.signatures[i].serial=="85:38:a6:c5:01:8f:50:fc")
}
