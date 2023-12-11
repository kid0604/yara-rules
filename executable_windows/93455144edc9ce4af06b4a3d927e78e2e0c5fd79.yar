import "pe"

rule INDICATOR_KB_CERT_186d49fac34ce99775b8e7ffbf50679d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "812a80556775d658450362e1b3650872b91deba44fef28f17c9364add5aa398e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hairis LLC" and pe.signatures[i].serial=="18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d")
}
