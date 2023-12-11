import "pe"

rule OilRig_Malware_Campaign_Mal2
{
	meta:
		description = "Detects malware from OilRig Campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/QMRZ8K"
		date = "2016-10-12"
		hash1 = "65920eaea00764a245acb58a3565941477b78a7bcc9efaec5bf811573084b6cf"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-C" ascii
		$x2 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
		$x3 = "mailto:Mohammed.sarah@gratner.com" fullword wide
		$x4 = "mailto:Tarik.Imam@gartner.com" fullword wide
		$x5 = "Call Extract(DnsPs1, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\dns.ps1\")" fullword ascii
		$x6 = "2dy53My5vcmcvMjAw" fullword wide

	condition:
		( uint16(0)==0xcfd0 and filesize <200KB and 1 of them )
}
