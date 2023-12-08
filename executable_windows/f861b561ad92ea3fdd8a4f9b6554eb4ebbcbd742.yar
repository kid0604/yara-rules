rule QQBrowser
{
	meta:
		description = "Not malware but suspicious browser - file QQBrowser.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		score = 50
		hash1 = "adcf6b8aa633286cd3a2ce7c79befab207802dec0e705ed3c74c043dabfc604c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "TerminateProcessWithoutDump" fullword ascii
		$s2 = ".Downloader.dll" fullword wide
		$s3 = "Software\\Chromium\\BrowserCrashDumpAttempts" fullword wide
		$s4 = "QQBrowser_Broker.exe" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
