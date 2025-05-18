rule SUSP_EXPL_Cleo_Exploitation_XML_Indicators_Dec24_1
{
	meta:
		author = "X__Junior"
		description = "Detects XML used during and after Cleo software exploitation (as reported by Huntress in December 2024)"
		reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
		hash1 = "b103f708e85416fc6d7af9605da4b57b3abe42fb9c6c9ec0f539b4c877580bd2"
		date = "2024-12-10"
		score = 70
		id = "b30ca09f-b84c-5de8-9bf7-9f3269f32c1f"
		os = "windows"
		filetype = "script"

	strings:
		$sa1 = "<Action actiontype=\"Commands\"" ascii
		$sa2 = "<?xml version=" ascii
		$sa3 = "<Runninglocalrequired>" ascii
		$sa4 = "<Autostartup>" ascii
		$sb1 = "[System.Net.WebRequest]::create" ascii
		$sb2 = "Invoke-RestMethod" ascii
		$sb3 = "Invoke-WebRequest" ascii
		$sb4 = "iwr " ascii
		$sb5 = "Net.WebClient" ascii
		$sb6 = "Resume-BitsTransfer" ascii
		$sb7 = "Start-BitsTransfer" ascii
		$sb8 = "wget " ascii
		$sb9 = "WinHttp.WinHttpRequest" ascii
		$sb10 = ".DownloadFile(" ascii
		$sb11 = ".DownloadString(" ascii
		$sb12 = "Bypass" nocase ascii
		$sb13 = "-EncodedCommand" ascii
		$sb14 = "-windowstyle hidden" ascii
		$sb15 = " -enc " ascii

	condition:
		filesize <10KB and all of ($sa*) and 1 of ($sb*)
}
