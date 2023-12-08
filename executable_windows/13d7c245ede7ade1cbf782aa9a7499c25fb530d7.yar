import "pe"

rule Nighthawk
{
	meta:
		author = "Nikhil Ashok Hegde <@ka1do9>"
		description = "NightHawk C2"
		cape_type = "Nighthawk Payload"
		os = "windows"
		filetype = "executable"

	strings:
		$keying_methods = { 85 C9 74 43 83 E9 01 74 1C 83 F9 01 0F 85 }
		$aes_sbox = { 63 7C 77 7B F2 6B 6F C5 30 }
		$aes_inv_sbox = { 52 09 6A D5 30 36 A5 38 BF }

	condition:
		pe.is_pe and for any s in pe.sections : (s.name==".profile") and all of them
}
