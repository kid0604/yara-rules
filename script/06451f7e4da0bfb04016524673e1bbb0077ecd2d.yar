rule INDICATOR_TOOL_PET_SharpWMI
{
	meta:
		author = "ditekSHen"
		description = "Detects SharpWMI"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "scriptKillTimeout" fullword ascii
		$s2 = "RemoteWMIExecuteWithOutput" fullword ascii
		$s3 = "RemoteWMIFirewall" fullword ascii
		$s4 = "iex([char[]](@({0})|%{{$_-bxor{1}}}) -join '')" fullword wide
		$s5 = "\\\\{0}\\root\\subscription" fullword wide
		$s6 = "_Context##RANDOM##" fullword wide
		$s7 = "executevbs" fullword wide
		$s8 = "scriptb64" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
