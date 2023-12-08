import "pe"

rule INDICATOR_KB_CERT_6d688ecf46286fe4b6823b91384eca86
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "970205140b48d684d0dc737c0fe127460ccfac4f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AtomPark Software JSC" and pe.signatures[i].serial=="6d:68:8e:cf:46:28:6f:e4:b6:82:3b:91:38:4e:ca:86")
}
