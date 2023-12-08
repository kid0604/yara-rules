rule Empire__Users_neo_code_Workspace_Empire_4sigs_PowerUp
{
	meta:
		description = "Detects Empire component - file PowerUp.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
		os = "windows"
		filetype = "script"

	strings:
		$x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii

	condition:
		( uint16(0)==0x233c and filesize <2000KB and 1 of them ) or all of them
}
