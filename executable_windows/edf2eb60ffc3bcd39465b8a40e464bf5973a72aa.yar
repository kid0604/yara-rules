import "pe"

rule MALWARE_Win_ImminentRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects ImminentRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "abuse@imminentmethods.net" ascii
		$x2 = "Imminent-Monitor-" ascii
		$x3 = "AddressChangeListener" fullword ascii
		$x4 = "SevenZipHelper" fullword ascii
		$x5 = "WrapNonExceptionThrows" fullword ascii
		$s1 = "_ENABLE_PROFILING" wide
		$s2 = "Anti-Virus: {0}" wide
		$s3 = "File downloaded & executed" wide
		$s4 = "Chat - You are speaking with" wide
		$s5 = "\\Imminent\\Plugins" wide
		$s6 = "\\Imminent\\Path.dat" wide
		$s7 = "\\Imminent\\Geo.dat" wide
		$s8 = "DisableTaskManager = {0}" wide
		$s9 = "This client is already mining" wide
		$s10 = "Couldn't get AV!" wide
		$s11 = "Couldn't get FW!" wide

	condition:
		uint16(0)==0x5a4d and (4 of ($x*) or 5 of ($s*))
}
