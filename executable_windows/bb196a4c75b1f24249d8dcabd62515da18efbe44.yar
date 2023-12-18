import "pe"

rule INDICATOR_KB_CERT_eda0f47b3b38e781cdf6ef6be5d3f6ee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1ef38b7c430c09062f4408c47da14d814be5e2e99749e65a2cf097f5610024fc"
		reason = "Matanbuchus"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ADVANCED ACCESS SERVICES LTD" and pe.signatures[i].serial=="ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee")
}
