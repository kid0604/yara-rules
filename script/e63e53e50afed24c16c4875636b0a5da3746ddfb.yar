rule Suspicious_PowerShell_WebDownload_1 : HIGHVOL FILE
{
	meta:
		description = "Detects suspicious PowerShell code that downloads from web sites"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		reference = "Internal Research"
		date = "2017-02-22"
		modified = "2022-07-27"
		nodeepdive = 1
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
		$s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
		$s3 = "system.net.webclient).downloadfile('http" ascii nocase
		$s4 = "system.net.webclient).downloadfile(\"http" ascii nocase
		$s5 = "GetString([Convert]::FromBase64String(" ascii nocase
		$fp1 = "NuGet.exe" ascii fullword
		$fp2 = "chocolatey.org" ascii
		$fp3 = " GET /"
		$fp4 = " POST /"
		$fp5 = ".DownloadFile('https://aka.ms/installazurecliwindows', 'AzureCLI.msi')" ascii
		$fp6 = " 404 "
		$fp7 = "# RemoteSSHConfigurationScript" ascii
		$fp8 = "<helpItems" ascii fullword
		$fp9 = "DownloadFile(\"https://codecov.io/bash" ascii

	condition:
		1 of ($s*) and not 1 of ($fp*)
}
