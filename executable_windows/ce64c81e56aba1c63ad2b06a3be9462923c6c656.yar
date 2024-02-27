rule AgentTeslaV5
{
	meta:
		author = "ClaudioWayne"
		description = "AgentTeslaV5 infostealer payload"
		cape_type = "AgentTesla payload"
		sample = "893f4dc8f8a1dcee05a0840988cf90bc93c1cda5b414f35a6adb5e9f40678ce9"
		os = "windows"
		filetype = "executable"

	strings:
		$template1 = "<br>User Name: " fullword wide
		$template2 = "<br>Username: " fullword wide
		$template3 = "<br>RAM: " fullword wide
		$template4 = "<br>Password: " fullword wide
		$template5 = "<br>OSFullName: " fullword wide
		$template6 = "<br><hr>Copied Text: <br>" fullword wide
		$template7 = "<br>CPU: " fullword wide
		$template8 = "<br>Computer Name: " fullword wide
		$template9 = "<br>Application: " fullword wide
		$chromium_browser1 = "Comodo\\Dragon\\User Data" fullword wide
		$chromium_browser2 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" fullword wide
		$chromium_browser3 = "Google\\Chrome\\User Data" fullword wide
		$chromium_browser4 = "Elements Browser\\User Data" fullword wide
		$chromium_browser5 = "Yandex\\YandexBrowser\\User Data" fullword wide
		$chromium_browser6 = "MapleStudio\\ChromePlus\\User Data" fullword wide
		$mozilla_browser1 = "\\Mozilla\\SeaMonkey\\" fullword wide
		$mozilla_browser2 = "\\K-Meleon\\" fullword wide
		$mozilla_browser3 = "\\NETGATE Technologies\\BlackHawk\\" fullword wide
		$mozilla_browser4 = "\\Thunderbird\\" fullword wide
		$mozilla_browser5 = "\\8pecxstudios\\Cyberfox\\" fullword wide
		$mozilla_browser6 = "360Chrome\\Chrome\\User Data" fullword wide
		$mozilla_browser7 = "\\Mozilla\\Firefox\\" fullword wide
		$configvariable1 = "PublicIpAddressGrab" fullword ascii
		$configvariable2 = "EnableClipboardLogger" fullword ascii
		$configvariable3 = "EnableTorPanel" fullword ascii
		$configvariable4 = "EnableKeylogger" fullword ascii
		$configvariable5 = "EnableSmartLogger" fullword ascii
		$configvariable6 = "DeleteBackspace" fullword ascii
		$configvariable7 = "StartupInstallationName" fullword ascii
		$configvariable8 = "PublicUserAgent" fullword ascii
		$database1 = "Berkelet DB" fullword wide
		$database2 = " 1.85 (Hash, version 2, native byte-order)" fullword wide
		$database3 = "00061561" fullword wide
		$database4 = "key4.db" fullword wide
		$database5 = "key3.db" fullword wide
		$database6 = "global-salt" fullword wide
		$database7 = "password-check" fullword wide
		$software1 = "\\FileZilla\\recentservers.xml" fullword wide
		$software2 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
		$software3 = "\\The Bat!" fullword wide
		$software4 = "\\Apple Computer\\Preferences\\keychain.plist" fullword wide
		$software5 = "\\MySQL\\Workbench\\workbench_user_data.dat" fullword wide
		$software6 = "\\Trillian\\users\\global\\accounts.dat" fullword wide
		$software7 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" fullword wide
		$software8 = "FTP Navigator\\Ftplist.txt" fullword wide
		$software9 = "NordVPN" fullword wide
		$software10 = "JDownloader 2.0\\cfg" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of ($template*) and 3 of ($chromium_browser*) and 3 of ($mozilla_browser*) and 4 of ($configvariable*) and 3 of ($database*) and 5 of ($software*)
}
