import "pe"

rule MALWARE_Win_NanoCore
{
	meta:
		author = "ditekSHen"
		description = "Detects NanoCore"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "NanoCore Client" fullword ascii
		$x2 = "NanoCore.ClientPlugin" fullword ascii
		$x3 = "NanoCore.ClientPluginHost" fullword ascii
		$i1 = "IClientApp" fullword ascii
		$i2 = "IClientData" fullword ascii
		$i3 = "IClientNetwork" fullword ascii
		$i4 = "IClientAppHost" fullword ascii
		$i5 = "IClientDataHost" fullword ascii
		$i6 = "IClientLoggingHost" fullword ascii
		$i7 = "IClientNetworkHost" fullword ascii
		$i8 = "IClientUIHost" fullword ascii
		$i9 = "IClientNameObjectCollection" fullword ascii
		$i10 = "IClientReadOnlyNameObjectCollection" fullword ascii
		$s1 = "ClientPlugin" fullword ascii
		$s2 = "EndPoint" fullword ascii
		$s3 = "IPAddress" fullword ascii
		$s4 = "IPEndPoint" fullword ascii
		$s5 = "IPHostEntr" fullword ascii
		$s6 = "get_ClientSettings" fullword ascii
		$s7 = "get_Connected" fullword ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($x*) or 8 of ($i*) or all of ($s*) or (1 of ($x*) and (3 of ($i*) or 2 of ($s*))))
}
