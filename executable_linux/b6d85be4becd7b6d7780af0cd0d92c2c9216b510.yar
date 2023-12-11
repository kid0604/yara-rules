rule Linux_Trojan_Mirai_eb940856
{
	meta:
		author = "Elastic Security"
		id = "eb940856-60d2-4148-9126-aac79a24828e"
		fingerprint = "01532c6feda3487829ad005232d30fe7dde5e37fd7cecd2bb9586206554c90a7"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "fbf814c04234fc95b6a288b62fb9513d6bbad2e601b96db14bb65ab153e65fef"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 84 24 80 00 00 00 31 C9 EB 23 48 89 4C 24 38 48 8D 84 24 C8 00 }

	condition:
		all of them
}
