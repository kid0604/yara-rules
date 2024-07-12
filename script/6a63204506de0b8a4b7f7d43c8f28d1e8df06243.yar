rule SUSP_BAT_OBFUSC_Jul24_3
{
	meta:
		description = "Detects indicators of obfuscation in Windows Batch files"
		author = "Florian Roth"
		reference = "https://x.com/0xToxin/status/1811656147943752045"
		date = "2024-07-12"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "% \\\\%"
		$s2 = { 3D ?? 26 26 73 65 74 20 }

	condition:
		filesize <300KB and all of them
}
