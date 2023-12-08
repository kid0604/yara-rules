import "pe"

rule Invoke_Metasploit_alt_1
{
	meta:
		description = "Detects Invoke-Metasploit Payload"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1"
		date = "2017-09-23"
		hash1 = "b36d3ca7073741c8a48c578edaa6d3b6a8c3c4413e961a83ad08ad128b843e0b"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "[*] Looks like we're 64bit, using regular powershell.exe" ascii wide
		$s2 = "[*] Kicking off download cradle in a new process"
		$s3 = "Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('''+$url+''');'"

	condition:
		( filesize <20KB and 1 of them )
}
