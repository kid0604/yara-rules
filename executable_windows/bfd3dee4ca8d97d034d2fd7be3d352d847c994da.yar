import "pe"

rule INDICATOR_KB_CERT_00ea734e1dfb6e69ed2bc55e513bf95b5e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5ca53cc5c6dc47838bbba922ad217a468408a9bd"
		hash1 = "293a83bfe2839bfa6d40fa52f5088e43b62791c08343c3f4dade4f1118000392"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Postmarket LLC" and (pe.signatures[i].serial=="00:ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e" or pe.signatures[i].serial=="ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e"))
}
