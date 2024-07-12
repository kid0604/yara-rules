rule SUSP_BAT_OBFUSC_Jul24_2
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
		filesize <300KB and #s1>30 and uint16( filesize -2)==0x0a0d and uint8( filesize -3)==0x25
}
