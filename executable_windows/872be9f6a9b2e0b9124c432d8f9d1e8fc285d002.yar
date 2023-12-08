rule APT_HKTL_Wiper_WhisperGate_Stage3_Jan22
{
	meta:
		description = "Detects reversed stage3 related to Ukrainian wiper malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/juanandres_gs/status/1482827018404257792"
		date = "2022-01-16"
		hash1 = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
		os = "windows"
		filetype = "executable"

	strings:
		$xc1 = { 65 31 63 70 00 31 79 72 61 72 62 69 4c 73 73 61 6c 43 00 6e 69 61 4d }
		$s1 = "lld." wide

	condition:
		uint16( filesize -2)==0x4d5a and filesize <5000KB and all of them
}
