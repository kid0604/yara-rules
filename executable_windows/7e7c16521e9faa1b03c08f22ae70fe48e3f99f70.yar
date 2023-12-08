rule MiniTor
{
	meta:
		id = "2kfngTvJBttBM67MLYYyil"
		fingerprint = "035c4826400ab70d1fa44a6452e1c738851994d3215e8d944f33b9aa2d409fe0"
		version = "1.0"
		creation_date = "2021-03-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies MiniTor implementation as seen in SystemBC and Parallax RAT."
		category = "MALWARE"
		malware_type = "RAT"
		reference = "https://news.sophos.com/en-us/2020/12/16/systembc/"
		os = "windows"
		filetype = "executable"

	strings:
		$code1 = {55 8b ec 81 c4 f0 fd ff ff 51 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 6a 0f 8d ?? 00 fe ff ff 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d ?? 0f fe ff ff 50 6a 14 ff 
        7? ?? e8 ?? ?? ?? ?? 8d ?? fc fd ff ff 50 8d ?? 00 fe ff ff 50 ff 7? ?? ff 7? ?? e8 ?? ?? 
        ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 8b b? ?? ?? ?? ?? 89 8? ?? ?? ?? ?? 68 ?? ?? ?? ?? ff b? ?? 
        ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 2b c7 03 f8 29 8? ?? ?? ?? ?? 68 ?? 
        ?? ?? ?? ff b? ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 85 c0 74 ?? 8b f7 83 c6 1e 8d ?? 00 fe ff ff c6}
		$code2 = {55 8b ec 81 c4 78 f8 ff ff 53 57 56 8d ?? f4 2b cc 51 8d ?? ?4 10 50 e8 ?? ?? ?? 
        ?? 68 00 00 00 f0 6a 0d 68 ?? ?? ?? ?? 6a 00 8d ?? fc 50 e8 ?? ?? ?? ?? 6a 00 6a 00 8d 05 
        ?? ?? ?? ?? 5? 8d ?? f8 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 
        ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f4 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? 
        ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 00 8d 05 ?? ?? ?? ?? 5? 8d ?? f0 50 68 ?? ?? ?? ?? 
        e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? ff d0 6a 00 6a 20 8d 05 ?? ?? ?? ?? 5? 8d 
        05 ?? ?? ?? ?? 5? ff 7? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50}

	condition:
		any of them
}
