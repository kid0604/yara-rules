import "pe"

rule APT_APT34_PS_Malware_Apr19_3
{
	meta:
		description = "Detects APT34 PowerShell malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
		date = "2019-04-17"
		modified = "2023-01-06"
		hash1 = "27e03b98ae0f6f2650f378e9292384f1350f95ee4f3ac009e0113a8d9e2e14ed"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Powershell.exe -exec bypass -file ${global:$address1}"
		$x2 = "schtasks /create /F /ru SYSTEM /sc minute /mo 10 /tn"
		$x3 = "\"\\UpdateTasks\\UpdateTaskHosts\""
		$x4 = "wscript /b \\`\"${global:$address1" ascii
		$x5 = "::FromBase64String([string]${global:$http_ag}))" ascii
		$x6 = ".run command1, 0, false\" | Out-File " ascii
		$x7 = "\\UpdateTask.vbs" ascii
		$x8 = "hUpdater.ps1" fullword ascii

	condition:
		1 of them
}
