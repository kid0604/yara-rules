rule INDICATOR_TOOL_NSudo
{
	meta:
		author = "ditekShen"
		description = "Detects NSudo allowing to run processes as TrustedInstaller or System"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd /c start \"NSudo." wide
		$x2 = "*\\shell\\NSudo" fullword wide
		$x3 = "Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb" ascii
		$s1 = "-ShowWindowMode=Hide" wide
		$s2 = "?what@exception@@UEBAPEBDXZ" fullword ascii
		$s3 = "NSudo.RunAs." ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or all of ($s*) or 4 of them )
}
