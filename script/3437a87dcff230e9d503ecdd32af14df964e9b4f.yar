rule p0wnedPowerCat
{
	meta:
		description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat.cs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/Cn33liz/p0wnedShell"
		date = "2017-01-14"
		hash1 = "6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Now if we point Firefox to http://127.0.0.1" fullword ascii
		$x2 = "powercat -l -v -p" fullword ascii
		$x3 = "P0wnedListener" fullword ascii
		$x4 = "EncodedPayload.bat" fullword ascii
		$x5 = "powercat -c " fullword ascii
		$x6 = "Program.P0wnedPath()" ascii
		$x7 = "Invoke-PowerShellTcpOneLine" fullword ascii

	condition:
		( uint16(0)==0x7375 and filesize <150KB and 1 of them ) or (2 of them )
}
