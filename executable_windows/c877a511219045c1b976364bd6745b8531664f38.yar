import "pe"

rule INDICATOR_KB_CERT_0aa099e64e214d655801ea38ad876711
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0789b35fd5c2ef8142e6aae3b58fff14e4f13136"
		hash1 = "9f90e6711618a1eab9147f90bdedd606fd975b785915ae37e50e7d2538682579"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Psiphon Inc." and pe.signatures[i].serial=="0a:a0:99:e6:4e:21:4d:65:58:01:ea:38:ad:87:67:11")
}
