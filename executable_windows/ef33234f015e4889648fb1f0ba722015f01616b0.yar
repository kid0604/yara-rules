import "pe"

rule KeyBoy_Dropper
{
	meta:
		Author = "Rapid7 Labs"
		Date = "2013/06/07"
		Description = "Strings inside"
		Reference = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"
		description = "Detects KeyBoy dropper based on specific strings inside the file"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "I am Admin"
		$2 = "I am User"
		$3 = "Run install success!"
		$4 = "Service install success!"
		$5 = "Something Error!"
		$6 = "Not Configed, Exiting"

	condition:
		all of them
}
