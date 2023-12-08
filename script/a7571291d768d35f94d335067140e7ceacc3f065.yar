rule SUSP_Script_Base64_Blocks_Jun20_1
{
	meta:
		description = "Detects suspicious file with base64 encoded payload in blocks"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://posts.specterops.io/covenant-v0-5-eee0507b85ba"
		date = "2020-06-05"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sa1 = "<script language=" ascii
		$sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 }

	condition:
		all of them
}
