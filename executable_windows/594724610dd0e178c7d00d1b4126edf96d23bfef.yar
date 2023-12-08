import "pe"

rule WoolenGoldfish_Generic_2
{
	meta:
		description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
		author = "Florian Roth"
		reference = "http://goo.gl/NpJpVZ"
		date = "2015/03/25"
		score = 90
		hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
		hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
		hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
		hash4 = "c1edf6e3a271cf06030cc46cbd90074488c05564"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii

	condition:
		all of them
}
