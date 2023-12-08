import "pe"

rule MALWARE_Win_HakunaMatata_Builder
{
	meta:
		author = "ditekSHen"
		description = "Detects HakunaMatata ransomware builder"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ENCRYPT FILES IN PROCESS" wide
		$s2 = "#TARGET_FILES" ascii wide
		$s3 = "HAKUNA MATATA" ascii wide nocase
		$s4 = "#PRIVATE_KEY" ascii wide
		$s5 = "/target:winexe /platform:anycpu /optimize+" wide
		$s6 = "/win32icon:" fullword wide
		$s7 = "SkippedFolders" ascii
		$s8 = "RECURSIVE_DIRECTORY_LOOK(" ascii
		$s9 = "DRAW_WALLPAPER(" ascii
		$s10 = "startupKey.SetValue(MESSAGE_FILE.Split('.')[0], executablePath);" ascii
		$s11 = /\\obj\\(Debug|Release)\\Hakuna\sMatata\.pdb/ ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
