rule p0wnedExploits
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedExploits.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "54548e7848e742566f5596d8f02eca1fd2cbfeae88648b01efb7bab014b9301b"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Pshell.RunPSCommand(Whoami);" fullword ascii
		$x2 = "If succeeded this exploit should popup a System CMD Shell" fullword ascii

	condition:
		all of them
}
