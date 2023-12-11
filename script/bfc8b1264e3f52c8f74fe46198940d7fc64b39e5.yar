import "pe"

rule OilRig_Malware_Campaign_Mal3
{
	meta:
		description = "Detects malware from OilRig Campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/QMRZ8K"
		date = "2016-10-12"
		hash1 = "02226181f27dbf59af5377e39cf583db15200100eea712fcb6f55c0a2245a378"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "(Get-Content $env:Public\\Libraries\\dns.ps1) -replace ('#'+'##'),$botid | Set-Content $env:Public\\Libraries\\dns.ps1" fullword ascii
		$x2 = "Invoke-Expression ($global:myhome+'tp\\'+$global:filename+'.bat > '+$global:myhome+'tp\\'+$global:filename+'.txt')" fullword ascii
		$x3 = "('00000000'+(convertTo-Base36(Get-Random -Maximum 46655)))" fullword ascii

	condition:
		( filesize <10KB and 1 of them )
}
