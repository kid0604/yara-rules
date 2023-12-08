import "pe"

rule INDICATOR_KB_CERT_74c94ef697dc9783f845d26dccc1e7fd
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6daa64d7af228de45ded86ad4d1aeaa360295f56"
		hash1 = "45e35c9b095871fbc9b85afff4e79dd36b7812b96a302e1ccc65ce7668667fe6"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CIBIKART d.o.o." and pe.signatures[i].serial=="74:c9:4e:f6:97:dc:97:83:f8:45:d2:6d:cc:c1:e7:fd")
}
