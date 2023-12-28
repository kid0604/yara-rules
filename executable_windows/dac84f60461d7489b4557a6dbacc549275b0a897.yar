rule BlackTech_Gh0stTimes_panel
{
	meta:
		description = "Gh0stTimes Panel"
		author = "JPCERT/CC Incident Response Group"
		hash = "18a696b09d0b7e41ad8ab6a05b84a3022f427382290ce58f079dec7b07e86165"
		os = "windows"
		filetype = "executable"

	strings:
		$msg1 = "[server]Listen on %s:%d successful" ascii wide
		$msg2 = "[client] connect to target %s ok" ascii wide
		$msg3 = "WriteFile failure, Close anti-virus software and try again." ascii wide
		$msg4 = "[server<-->client]begin portmap..." ascii wide
		$msg5 = "This folder already contains the file named %s" ascii wide
		$table1 = "CPortMapDlg" ascii wide
		$table2 = "CSettingDlg" ascii wide
		$table3 = "CShellDlg" ascii wide
		$table4 = "CFileManagerDlg" ascii wide
		$table5 = "CFileTransferModeDlg" ascii wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 5 of them
}
