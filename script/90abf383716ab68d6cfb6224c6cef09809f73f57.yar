rule APT_WebShell_AUS_JScript_3
{
	meta:
		description = "Detetcs a webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		hash1 = "7ac6f973f7fccf8c3d58d766dec4ab7eb6867a487aa71bc11d5f05da9322582d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<%@ Page Language=\"Jscript\" validateRequest=\"false\"%><%try{eval(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String" ascii
		$s2 = ".Item[\"[password]\"])),\"unsafe\");}" ascii

	condition:
		uint16(0)==0x6568 and filesize <1KB and all of them
}
