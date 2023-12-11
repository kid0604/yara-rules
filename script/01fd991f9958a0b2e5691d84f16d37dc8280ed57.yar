rule p0wnedPotato
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Invoke-Tater" fullword ascii
		$x2 = "P0wnedListener.Execute(WPAD_Proxy);" fullword ascii
		$x3 = " -SpooferIP " ascii
		$x4 = "TaterCommand()" ascii
		$x5 = "FileName = \"cmd.exe\"," fullword ascii

	condition:
		1 of them
}
