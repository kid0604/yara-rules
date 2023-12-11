import "pe"

rule INDICATOR_KB_CERT_0b2b192657b37632518b08a06e201381
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ea017224c3b209abf53941cc4110e93af7ecc7b1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Atomic Protocol Systems" and pe.signatures[i].serial=="0b:2b:19:26:57:b3:76:32:51:8b:08:a0:6e:20:13:81")
}
