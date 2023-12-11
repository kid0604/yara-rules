import "pe"

rule INDICATOR_KB_CERT_1b1e87e90519d7273c0033bf489b798f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ef09824554f85603c9ffb1cecbfe06ae489a9583"
		hash = "84cef0aed269e6213bfa213d95a3db625bcdde130f33bf4227436985e4473252"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IBIS, OOO" and pe.signatures[i].serial=="1b:1e:87:e9:05:19:d7:27:3c:00:33:bf:48:9b:79:8f")
}
