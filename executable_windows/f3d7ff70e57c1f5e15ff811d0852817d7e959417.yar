import "pe"

rule WiltedTulip_Windows_UM_Task
{
	meta:
		description = "Detects a Windows scheduled task as used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "4c2fc21a4aab7686877ddd35d74a917f6156e48117920d45a3d2f21fb74fedd3"
		os = "windows"
		filetype = "executable"

	strings:
		$r1 = "<Command>C:\\Windows\\syswow64\\rundll32.exe</Command>" fullword wide
		$p1 = "<Arguments>\"C:\\Users\\public\\" wide
		$c1 = "svchost64.swp\",checkUpdate" wide ascii
		$c2 = "svchost64.swp,checkUpdate" wide ascii

	condition:
		($r1 and $p1) or 1 of ($c*)
}
