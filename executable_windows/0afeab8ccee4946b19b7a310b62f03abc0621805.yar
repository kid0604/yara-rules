import "pe"

rule INDICATOR_KB_CERT_ceb6b2eec12934a64f75a4592159f084
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ccd30b68e37fc177b754250767a16062a711310a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WMade by H5et.com" and pe.signatures[i].serial=="ce:b6:b2:ee:c1:29:34:a6:4f:75:a4:59:21:59:f0:84")
}
