rule Lazarus_Dec_17_5
{
	meta:
		description = "Detects Lazarus malware from incident in Dec 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8U6fY2"
		date = "2017-12-20"
		hash1 = "db8163d054a35522d0dec35743cfd2c9872e0eb446467b573a79f84d61761471"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "$ProID = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList" fullword ascii
		$x2 = "$respTxt = HttpRequestFunc_doprocess -szURI $szFullURL -szMethod $szMethod -contentData $contentData;" fullword ascii
		$x3 = "[String]$PS_PATH = \"C:\\\\Users\\\\Public\\\\Documents\\\\ProxyAutoUpdate.ps1\";" fullword ascii
		$x4 = "$cmdSchedule = 'schtasks /create /tn \"ProxyServerUpdater\"" ascii
		$x5 = "/tr \"powershell.exe -ep bypass -windowstyle hidden -file " ascii
		$x6 = "C:\\\\Users\\\\Public\\\\Documents\\\\tmp' + -join " ascii
		$x7 = "$cmdResult = cmd.exe /c $cmdInst | Out-String;" fullword ascii
		$x8 = "whoami /groups | findstr /c:\"S-1-5-32-544\"" fullword ascii

	condition:
		filesize <500KB and 1 of them
}
