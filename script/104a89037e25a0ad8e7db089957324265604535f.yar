rule Empire_invoke_wmi
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file invoke_wmi.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "a914cb227f652734a91d3d39745ceeacaef7a8b5e89c1beedfd6d5f9b4615a1d"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii
		$s2 = "script += \";'Invoke-Wmi executed on \" +computerNames +\"'\"" fullword ascii
		$s3 = "script = \"$PSPassword = \\\"\"+password+\"\\\" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Man" ascii

	condition:
		filesize <20KB and 2 of them
}
