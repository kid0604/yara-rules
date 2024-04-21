rule case_19772_anydesk_installer
{
	meta:
		description = "19772 - file INSTALL.ps1"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
		date = "2024-01-09"
		hash1 = "b378c2aa759625de2ad1be2c4045381d7474b82df7eb47842dc194bb9a134f76"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "    cmd.exe /c echo btc1000qwe123 | C:\\ProgramData\\Any\\AnyDesk.exe --set-password" fullword ascii
		$x2 = "    cmd.exe /c C:\\ProgramData\\AnyDesk.exe --install C:\\ProgramData\\Any --start-with-win --silent" fullword ascii
		$s3 = "    #reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\" /v Inn" ascii
		$s4 = "    #reg add \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\" /v Inn" ascii
		$s5 = "    $url = \"http://download.anydesk.com/AnyDesk.exe\"" fullword ascii
		$s6 = "EG_DWORD /d 0 /f" fullword ascii
		$s7 = "    $file = \"C:\\ProgramData\\AnyDesk.exe\"" fullword ascii
		$s8 = "    $clnt = new-object System.Net.WebClient" fullword ascii
		$s9 = "    #net user AD \"2020\" /add" fullword ascii
		$s10 = "    # Download AnyDesk" fullword ascii
		$s11 = "    mkdir \"C:\\ProgramData\\Any\"" fullword ascii
		$s12 = "    $clnt.DownloadFile($url,$file)" fullword ascii
		$s13 = "    #net localgroup Administrators InnLine /ADD" fullword ascii

	condition:
		uint16(0)==0x0a0d and filesize <1KB and 1 of ($x*) and 4 of them
}
