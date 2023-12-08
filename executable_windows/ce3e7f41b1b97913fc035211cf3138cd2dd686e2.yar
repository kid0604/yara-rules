import "dotnet"

rule Prometei_Spreader
{
	meta:
		id = "EH3oMrAkcLfDxYgZXKd8o"
		fingerprint = "4eb71a189ef2651539d70f8202474394972a9dc0ad3218260c8af8a48e3ccdc5"
		version = "1.0"
		first_imported = "2023-03-24"
		last_modified = "2023-03-24"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies SSH spreader used by Prometei botnet, specifically windrlver."
		category = "MALWARE"
		malware = "PROMETEI"
		malware_type = "BOT"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
		os = "windows"
		filetype = "executable"

	strings:
		$code = {8a 01 41 84 c0 75 ?? 2b ce 8d 04 13 2b cb 03 c7 2b cf 51 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 83 c4 0c 33 db 8d 9b 00 00 00 00}

	condition:
		$code
}
