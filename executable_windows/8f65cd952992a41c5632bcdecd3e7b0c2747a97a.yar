import "pe"

rule INDICATOR_KB_CERT_2f38de4ced0b070973b9e9b9b1dcfa7f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "71382f6c6e48df51f15606380cd6948bf37f044d18566ebc2d262fc87e70b9b1"
		reason = "Gh0stRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fahad Malik" and pe.signatures[i].serial=="2f:38:de:4c:ed:0b:07:09:73:b9:e9:b9:b1:dc:fa:7f")
}
