rule malware_RestyLink_lnk
{
	meta:
		description = "RestyLink lnk file"
		author = "JPCERT/CC Incident Response Group"
		hash = "90a223625738e398d2cf0be8d37144392cc2e7d707b096a7bfc0a52b408d98b1"
		hash = "9aa2187dbdeef231651769ec8dc5f792c2a9a7233fbbbcf383b05ff3d6179fcf"
		hash = "3feb9275050827543292a97cbf18c50c552a1771c4423c4df4f711a39696ed93"
		os = "windows"
		filetype = "executable"

	strings:
		$cmd1 = "C:\\Windows\\System32\\cmd.exe" wide
		$cmd2 = "Windows\\system32\\ScriptRunner.exe" wide
		$command1 = "/c set a=start winword.exe /aut&&set" wide
		$command2 = "&&set n=omation /vu /q&&cmd /c %a%%n% %m%" wide
		$command3 = "-appvscript explorer.exe https://" wide
		$command4 = "-appvscript curl.exe -s https://" wide

	condition:
		uint16(0)==0x004c and filesize <100KB and 1 of ($cmd*) and 1 of ($command*)
}
