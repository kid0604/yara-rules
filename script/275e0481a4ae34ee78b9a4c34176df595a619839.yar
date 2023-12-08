rule APT_NK_Scarcruft_RUBY_Shellcode_XOR_Routine
{
	meta:
		author = "S2WLAB_TALON_JACK2"
		description = "Detects Ruby ShellCode XOR routine used by ScarCruft APT group"
		type = "APT"
		version = "0.1"
		date = "2021-05-20"
		reference = "https://medium.com/s2wlab/matryoshka-variant-of-rokrat-apt37-scarcruft-69774ea7bf48"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$hex1 = {C1 C7 0D 40 F6 C7 01 74 ?? 81 F7}
		$hex2 = {41 C1 C2 0D 41 8B C2 44 8B CA 41 8B CA 41 81 F2}

	condition:
		1 of them
}
