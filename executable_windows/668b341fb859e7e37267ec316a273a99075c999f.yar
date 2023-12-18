import "pe"

rule INDICATOR_KB_CERT_4659fa5fc1e0397df79fd6a4083d93b0
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "fa5f2dbe813b0270b1f9e53da1be024fb495e8b1848bb3c9c7392a40c8f7e8e6"
		reason = "RedLineStealer"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Incuber Services LLP" and pe.signatures[i].serial=="46:59:fa:5f:c1:e0:39:7d:f7:9f:d6:a4:08:3d:93:b0")
}
