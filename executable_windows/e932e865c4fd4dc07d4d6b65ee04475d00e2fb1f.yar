import "pe"

rule MALWARE_Win_XenoRAT
{
	meta:
		author = "ditekshen"
		description = "Detects Blacksuit"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "xeno rat client" wide
		$x2 = "xeno_rat_client." ascii
		$x3 = "xeno rat client" ascii
		$s1 = "+<AddToStartupNonAdmin>" ascii
		$s2 = "+<ConnectAndSetupAsync>" ascii
		$s3 = "+<SendUpdateInfo>" ascii
		$s4 = "+<RecvAllAsync_ddos_" ascii
		$s5 = "Plugin.Chromium+<Get" ascii

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and 2 of ($s*)) or (4 of ($s*)) or (2 of ($x*)))
}
