rule zipExec : WindowsMalware
{
	meta:
		author = "Marius 'f0wL' Genheimer <hello@dissectingmalwa.re>"
		description = "Detects zipExec Golang Loader/Crypter"
		reference = "https://github.com/Tylous/ZipExec"
		date = "2021-10-29"
		tlp = "WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$shellExec = "ShellExecute('cmdkey', '/generic:Microsoft_Windows_Shell_ZipFolder:filename=" ascii
		$domainCheck = "GetSystemInformation(\"IsOS_DomainMember\");" ascii
		$tmp = "GetSpecialFolder(2);" ascii
		$wscript = "new ActiveXObject(\"Wscri\"+\"pt.shell\");" ascii
		$regExt = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\HideFileExt" ascii
		$base64Index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" ascii
		$zipEnc = {55 45 73 44 42 42 51 41 43 51 41 49 41 41}

	condition:
		uint16(0)==0x090a and filesize <10MB and $zipEnc and 5 of them
}
