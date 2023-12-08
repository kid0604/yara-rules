import "pe"

private rule GmRemoteStrings : GmRemote Variant Family Surtr
{
	meta:
		description = "identifiers for gmremote: surtr stage 2"
		author = "Katie Kleemola"
		last_updated = "07-21-2014"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "\x00x86_GmRemote.dll\x00"
		$ = "\x00D:\\Project\\GTProject\\Public\\List\\ListManager.cpp\x00"
		$ = "\x00GmShutPoint\x00"
		$ = "\x00GmRecvPoint\x00"
		$ = "\x00GmInitPoint\x00"
		$ = "\x00GmVerPoint\x00"
		$ = "\x00GmNumPoint\x00"
		$ = "_Gt_Remote_" wide
		$ = "%sBurn\\workdll.tmp" wide

	condition:
		any of them
}
