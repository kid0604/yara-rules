rule Possible_Solarmarker_Backdoor_Nov2023
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "Observed strings in the latest obfuscated solarmarker backdoor dll."
		reference = "https://security5magics.blogspot.com/2023/10/new-solarmarker-variant-october-2023.html"
		os = "windows"
		filetype = "executable"

	strings:
		$a = /\x00<Module>\x00[a-zA-Z0-9]{40}/ ascii
		$h1 = {54 68 72 65 61 64 00 53 6C 65 65 70}
		$h2 = {54 68 72 65 61 64 00 53 74 61 72 74}
		$b = /\x00Select\x00[a-zA-Z0-9_]{40}/ ascii
		$c = "GenerateIV" ascii
		$d = "$$method0x" ascii

	condition:
		$a and $b and $c and $d and ($h1 or $h2)
}
