rule Vermin_Keylogger_Jan18_1
{
	meta:
		description = "Detects Vermin Keylogger"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-vermin-quasar-rat-custom-malware-used-ukraine/"
		date = "2018-01-29"
		hash1 = "74ba162eef84bf13d1d79cb26192a4692c09fed57f321230ddb7668a88e3935d"
		hash2 = "e1d917769267302d58a2fd00bc49d4aee5a472227a75f9366b46ce243e9cbef7"
		hash3 = "0157b43eb3c20928b77f8700ad8eb279a0aa348921df074cd22ebaff01edaae6"
		hash4 = "4c5e019e0e55a3fe378aa339d52c235c06ecc5053625a5d54d65c4ae38c6e3da"
		hash5 = "24956d8edcf2a1fd26805ec58cfd1ee7498e1a59af8cc2f4b832a7ab34948c18"
		hash6 = "2963c5eacaad13ace807edd634a4a5896cb5536f961f43afcf8c1f25c08a5eef"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "_keyloggerTaskDescription" ascii
		$x2 = "_keyloggerTaskAuthor" ascii
		$x3 = "GetKeyloggerLogsResponse" fullword ascii
		$x4 = "GetKeyloggerLogs" fullword ascii
		$x5 = "ExecuteUninstallKeyLoggerTask" fullword ascii
		$x6 = "ExecuteInstallKeyLoggerTask" fullword ascii
		$x7 = ":\\Projects\\Vermin\\KeyboardHookLib\\" ascii
		$x8 = ":\\Projects\\Vermin\\CryptoLib\\" ascii
		$s1 = "<RunHidden>k__BackingField" fullword ascii
		$s2 = "set_SystemInfos" fullword ascii
		$s3 = "set_RunHidden" fullword ascii
		$s4 = "set_RemotePath" fullword ascii
		$s5 = "ExecuteShellCommandTask" fullword ascii
		$s6 = "Client.exe" fullword wide
		$s7 = "xClient.Core.ReverseProxy.Packets" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and (1 of ($x*) or 3 of them )
}
