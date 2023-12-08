rule email_Ukraine_power_attack_attachment : mail
{
	meta:
		author = " @yararules"
		description = "Detects a possible .eml used in the Ukraine BE power attack"
		ref1 = "https://twitter.com/lowcalspam/status/692625258394726400"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$filename = "filename=\"=?windows-1251?B?xO7k4PLu6jEueGxz?=\""

	condition:
		all of them
}
