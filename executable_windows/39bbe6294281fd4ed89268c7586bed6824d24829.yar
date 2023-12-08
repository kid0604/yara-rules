import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_SandboxProductID
{
	meta:
		description = "Detects binaries and memory artifcats referencing sandbox product IDs"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$id1 = "76487-337-8429955-22614" fullword ascii wide
		$id2 = "76487-644-3177037-23510" fullword ascii wide
		$id3 = "55274-640-2673064-23950" fullword ascii wide
		$id4 = "76487-640-1457236-23837" fullword ascii wide
		$id5 = "76497-640-6308873-23835" fullword ascii wide
		$id6 = "76487-640-1464517-23259" fullword ascii wide
		$id7 = "76487 - 337 - 8429955 - 22614" fullword ascii wide
		$id8 = "76487 - 644 - 3177037 - 23510" fullword ascii wide
		$id9 = "55274 - 640 - 2673064 - 23950" fullword ascii wide
		$id10 = "76487 - 640 - 1457236 - 23837" fullword ascii wide
		$id11 = "76497 - 640 - 6308873 - 23835" fullword ascii wide
		$id12 = "76487 - 640 - 1464517 - 23259" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and 2 of them
}
