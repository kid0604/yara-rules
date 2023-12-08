import "pe"

rule INDICATOR_KB_CERT_00b2e730b0526f36faf7d093d48d6d9997
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "10dd41eb9225b615e6e4f1dce6690bd2c8d055f07d4238db902f3263e62a04a9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bamboo Connect s.r.o." and pe.signatures[i].serial=="00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97")
}
