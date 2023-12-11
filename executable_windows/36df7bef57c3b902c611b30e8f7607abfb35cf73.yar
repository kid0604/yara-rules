import "pe"

rule INDICATOR_KB_CERT_56fff139df5ae7e788e5d72196dd563a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0f69ccb73a6b98f548d00f0b740b6e42907efaad"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cifromatika LLC" and pe.signatures[i].serial=="56:ff:f1:39:df:5a:e7:e7:88:e5:d7:21:96:dd:56:3a")
}
