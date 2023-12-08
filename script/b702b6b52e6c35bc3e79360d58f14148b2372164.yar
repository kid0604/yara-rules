import "pe"

rule OilRig_Malware_Campaign_Mal1
{
	meta:
		description = "Detects malware from OilRig Campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/QMRZ8K"
		date = "2016-10-12"
		hash1 = "e17e1978563dc10b73fd54e7727cbbe95cc0b170a4e7bd0ab223e059f6c25fcc"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "DownloadExecute=\"powershell \"\"&{$r=Get-Random;$wc=(new-object System.Net.WebClient);$wc.DownloadFile(" ascii
		$x2 = "-ExecutionPolicy Bypass -File \"&HOME&\"dns.ps1\"" fullword ascii
		$x3 = "CreateObject(\"WScript.Shell\").Run Replace(DownloadExecute,\"-_\",\"bat\")" fullword ascii
		$x4 = "CreateObject(\"WScript.Shell\").Run DnsCmd,0" fullword ascii
		$s1 = "http://winodwsupdates.me" ascii

	condition:
		( uint16(0)==0x4f48 and filesize <4KB and 1 of them ) or (2 of them )
}
