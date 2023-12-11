rule p0wnedAmsiBypass
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Program.P0wnedPath()" fullword ascii
		$x2 = "namespace p0wnedShell" fullword ascii
		$x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii

	condition:
		1 of them
}
