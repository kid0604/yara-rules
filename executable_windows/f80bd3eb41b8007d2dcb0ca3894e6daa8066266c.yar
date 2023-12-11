rule WildNeutron_Sample_4
{
	meta:
		description = "Wild Neutron APT Sample Rule - file b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "b4005530193bc523d3e0193c3c53e2737ae3bf9f76d12c827c0b5cd0dcbaae45"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "WinRAT-Win32-Release.exe" fullword ascii
		$s0 = "rundll32.exe \"%s\",#1" fullword wide
		$s1 = "RtlUpd.EXE" fullword wide
		$s2 = "RtlUpd.exe" fullword wide
		$s3 = "Driver Update and remove for Windows x64 or x86_32" fullword wide
		$s4 = "Realtek HD Audio Update and remove driver Tool" fullword wide
		$s5 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
		$s6 = "Key Usage" fullword ascii
		$s7 = "id-at-serialNumber" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1240KB and all of them
}
