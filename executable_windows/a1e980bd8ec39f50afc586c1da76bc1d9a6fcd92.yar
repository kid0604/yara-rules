rule Lazarus_msi_str
{
	meta:
		description = "msi file using Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "f0b6d6981e06c7be2e45650e5f6d39570c1ee640ccb157ddfe42ee23ad4d1cdb"
		os = "windows"
		filetype = "executable"

	strings:
		$magic = /^\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1\x00\x00\x00/
		$s1 = "New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 300)" ascii wide
		$s2 = "New-ScheduledTaskAction -Execute \"c:\\windows\\system32\\pcalua.exe" ascii wide
		$s3 = "function sendbi(pd)" ascii wide
		$s4 = "\\n\\n\"+g_mac()+\"\\n\\n\"+g_proc()" ascii wide

	condition:
		$magic at 0 and 2 of ($s*)
}
