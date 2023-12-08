rule Empire_Persistence
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "ae8875f7fcb8b4de5cf9721a9f5a9f7782f7c436c86422060ecdc5181e31092f"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "C:\\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -V" ascii
		$s2 = "# Execute the following to remove the user-level persistent payload" fullword ascii
		$s3 = "$PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', \"$PersistenceScriptName -Persist\")" fullword ascii

	condition:
		filesize <108KB and 1 of them
}
