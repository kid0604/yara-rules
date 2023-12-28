rule BlackTech_IconDown_pe
{
	meta:
		description = "detect IconDown"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "PE file search"
		hash1 = "634839b452e43f28561188a476af462c301b47bddd0468dd8c4f452ae80ea0af"
		hash2 = "2e789fc5aa1318d0286264d70b2ececa15664689efa4f47c485d84df55231ac4"
		os = "windows"
		filetype = "executable"

	strings:
		$dataheader1 = { 91 00 13 87 33 00 90 06 19 00 }
		$dataheader2 = { C6 [2-3] 91 88 [2-3] C6 [2-3] 13 C6 [2-3] 87 C6 [2-3] 33 88 [2-3] C6 [2-3] 90 C6 [2-3] 06 C6 [2-3] 19 }
		$string1 = "/c %s" ascii
		$string2 = /%s\\[A-X]{1,3}%[l]{0,1}X\.TMP/

	condition:
		( uint16(0)==0x5A4D) and ( filesize <5MB) and 1 of ($dataheader*) and all of ($string*)
}
