rule Pastebin_Webshell
{
	meta:
		description = "Detects a web shell that downloads content from pastebin.com http://goo.gl/7dbyZs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		date = "13.01.2015"
		reference = "http://goo.gl/7dbyZs"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "file_get_contents(\"http://pastebin.com" ascii
		$s1 = "xcurl('http://pastebin.com/download.php" ascii
		$s2 = "xcurl('http://pastebin.com/raw.php" ascii
		$x0 = "if($content){unlink('evex.php');" ascii
		$x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii
		$y0 = "file_put_contents($pth" ascii
		$y1 = "echo \"<login_ok>" ascii
		$y2 = "str_replace('* @package Wordpress',$temp" ascii

	condition:
		1 of ($s*) or all of ($x*) or all of ($y*)
}
