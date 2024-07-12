rule SUSP_BAT_OBFUSC_Jul24_1
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
		$s1 = "&&set "

	condition:
		filesize <300KB and uint32(0)==0x20746573 and $s1 in (0..32)
}
