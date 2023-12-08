import "pe"

rule INDICATOR_KB_CERT_2c3e87b9d430c2f0b14fc1152e961f1a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "80daa4ad14fc420d7708f2855e6fab085ca71980"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Abfaacccde" and pe.signatures[i].serial=="2c:3e:87:b9:d4:30:c2:f0:b1:4f:c1:15:2e:96:1f:1a")
}
