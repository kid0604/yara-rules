import "pe"

rule INDICATOR_KB_CERT_3696883055975d571199c6b5d48f3cd5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "933749369d61bebd5f2c63ff98625973c41098462d9732cffaffe7e02823bc3a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Korist Networks Incorporated" and pe.signatures[i].serial=="36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5")
}
