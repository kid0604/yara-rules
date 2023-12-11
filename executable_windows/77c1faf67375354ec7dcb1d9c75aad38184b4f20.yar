rule INDICATOR_TOOL_NgrokSharp
{
	meta:
		author = "ditekSHen"
		description = "Detects NgrokSharp .NET library for Ngrok"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "NgrokSharp" fullword wide
		$x2 = "/entvex/NgrokSharp" ascii
		$s1 = "start --none -region" wide
		$s2 = "startTunnelDto" fullword wide
		$s3 = "/tunnels/" fullword wide
		$s4 = "<StartNgrok" ascii
		$s5 = "INgrokManager" ascii
		$s6 = "_tunnel_name" ascii
		$s7 = "_ngrokDownloadUrl" ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($x*) or (1 of ($x*) and 3 of ($s*)) or 4 of ($*))
}
