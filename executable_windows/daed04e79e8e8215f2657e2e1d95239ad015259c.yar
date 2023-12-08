rule Windows_Trojan_Raccoon_deb6325c
{
	meta:
		author = "Elastic Security"
		id = "deb6325c-5556-44ce-a184-6369105485d5"
		fingerprint = "17c34b5b9a0211255a93f9662857361680e72a45135d6ea9b5af8d77b54583b9"
		creation_date = "2022-06-28"
		last_modified = "2022-07-18"
		threat_name = "Windows.Trojan.Raccoon"
		reference_sample = "f7b1aaae018d5287444990606fc43a0f2deb4ac0c7b2712cc28331781d43ae27"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Raccoon"
		filetype = "executable"

	strings:
		$a1 = "\\ffcookies.txt" wide fullword
		$a2 = "wallet.dat" wide fullword
		$a3 = "0Network\\Cookies" wide fullword
		$a4 = "Wn0nlDEXjIzjLlkEHYxNvTAXHXRteWg0ieGKVyD52CvONbW7G91RvQDwSZi/N2ISm4xEWRKYJwjnYUGS9OZmj/TAie8jG07EXEcO8D7h2m2lGzWnFG31R1rsxG1+G8E="

	condition:
		all of them
}
