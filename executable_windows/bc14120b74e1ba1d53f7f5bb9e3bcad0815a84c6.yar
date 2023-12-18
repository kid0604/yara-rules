import "pe"

rule INDICATOR_KB_CERT_3628b93bcd902b6b3e1ffdf2e13dfcf5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "27b75dc1d31a581f6e02bba3c03a62174ee4456021c7de50922caa10b98f8f7a"
		reason = "Malware"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="36:28:b9:3b:cd:90:2b:6b:3e:1f:fd:f2:e1:3d:fc:f5")
}
