rule INDICATOR_TOOL_RTK_HiddenRootKit
{
	meta:
		author = "ditekSHen"
		description = "Detects the Hidden public rootkit"
		os = "windows"
		filetype = "executable"

	strings:
		$h1 = "Hid_State" fullword wide
		$h2 = "Hid_StealthMode" fullword wide
		$h3 = "Hid_HideFsDirs" fullword wide
		$h4 = "Hid_HideFsFiles" fullword wide
		$h5 = "Hid_HideRegKeys" fullword wide
		$h6 = "Hid_HideRegValues" fullword wide
		$h7 = "Hid_IgnoredImages" fullword wide
		$h8 = "Hid_ProtectedImages" fullword wide
		$s1 = "FLTMGR.SYS" fullword ascii
		$s2 = "HAL.dll" fullword ascii
		$s3 = "\\SystemRoot\\System32\\csrss.exe" fullword wide
		$s4 = "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\%wZ" fullword wide
		$s5 = "INIT" fullword ascii
		$s6 = "\\hidden-master\\Debug\\QAssist.pdb" fullword ascii

	condition:
		uint16(0)==0x5a4d and (3 of ($h*) or 5 of ($s*) or (2 of ($s*) and 2 of ($h*)))
}
