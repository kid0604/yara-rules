import "pe"

rule INDICATOR_KB_CERT_f90e68cbf92fd7ad409e281c3f2a0f0a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c202564339ddd78a1ce629ce54824ba2697fa3d6"
		hash = "d79a8f491c0112c3f26572350336fe7d22674f5550f37894643eba980ae5bd32"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SUCK-MY-DICK-ESET" and pe.signatures[i].serial=="f9:0e:68:cb:f9:2f:d7:ad:40:9e:28:1c:3f:2a:0f:0a")
}
