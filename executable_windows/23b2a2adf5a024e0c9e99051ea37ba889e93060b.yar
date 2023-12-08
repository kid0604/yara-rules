import "pe"

rule INDICATOR_KB_CERT_249e3f1b7595e7d0fe6df13303287343
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8e99b2786f59e543d1f3d02d140e35342c55c18a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "gsLPuSUgRZueWihiZHqYBriNSQqS" and pe.signatures[i].serial=="24:9e:3f:1b:75:95:e7:d0:fe:6d:f1:33:03:28:73:43")
}
