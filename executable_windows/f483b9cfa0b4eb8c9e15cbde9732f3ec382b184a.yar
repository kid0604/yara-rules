import "pe"

rule INDICATOR_KB_CERT_0f007898afcba5f8af8ae65d01803617
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5687481a453414e63e76e1135ed53f4bd0410b05"
		hash1 = "815f1f87e2df79e3078c63b3cb1ffb7d17fd24f6c7092b8bbe1f5f8ceda5df22"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TechnoElek s.r.o." and pe.signatures[i].serial=="0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17")
}
