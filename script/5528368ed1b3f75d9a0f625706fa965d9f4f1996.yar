rule CN_Honker_Webshell_PHP_php10
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php10.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3698c566a0ae07234c8957112cdb34b79362b494"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "dumpTable($N,$M,$Hc=false){if($_POST[\"format\"]!=\"sql\"){echo\"\\xef\\xbb\\xbf" ascii
		$s2 = "';if(DB==\"\"||!$od){echo\"<a href='\".h(ME).\"sql='\".bold(isset($_GET[\"sql\"]" ascii

	condition:
		filesize <600KB and all of them
}
