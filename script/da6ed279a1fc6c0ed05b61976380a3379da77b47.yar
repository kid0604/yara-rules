rule Empire_Exploit_Jenkins
{
	meta:
		description = "Detects Empire component - file Exploit-Jenkins.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "a5182cccd82bb9984b804b365e07baba78344108f225b94bd12a59081f680729"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$postdata=\"script=println+new+ProcessBuilder%28%27\"+$($Cmd)+\"" ascii
		$s2 = "$url = \"http://\"+$($Rhost)+\":\"+$($Port)+\"/script\"" fullword ascii
		$s3 = "$Cmd = [System.Web.HttpUtility]::UrlEncode($Cmd)" fullword ascii

	condition:
		( uint16(0)==0x6620 and filesize <7KB and 1 of them ) or all of them
}
