import "pe"

rule INDICATOR_KB_CERT_008d1bae9f7aef1a2bcc0d392f3edf3a36
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5927654acf9c66912ff7b41dab516233d98c9d72"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Beaffbebfeebbefbeeb" and pe.signatures[i].serial=="00:8d:1b:ae:9f:7a:ef:1a:2b:cc:0d:39:2f:3e:df:3a:36")
}
