rule Win_PrivEsc_ADACLScan4_3
{
	meta:
		description = "Detects a tool that can be used for privilege escalation - file ADACLScan4.3.ps1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://adaclscan.codeplex.com/"
		score = 60
		date = "2016-06-02"
		hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<Label x:Name=\"lblPort\" Content=\"Port:\"  HorizontalAlignment=\"Left\" Height=\"28\" Margin=\"10,0,0,0\" Width=\"35\"/>" fullword ascii
		$s2 = "(([System.IconExtractor]::Extract(\"mmcndmgr.dll\", 126, $true)).ToBitMap()).Save($env:temp + \"\\Other.png\")    " fullword ascii
		$s3 = "$bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)" fullword ascii

	condition:
		all of them
}
