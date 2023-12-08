rule fire2013 : webshell
{
	meta:
		author = "Vlad https://github.com/vlad-s"
		date = "2016/07/18"
		description = "Catches a webshell"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a = "eval(\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61"
		$b = "yc0CJYb+O//Xgj9/y+U/dd//vkf'\\x29\\x29\\x29\\x3B\")"

	condition:
		all of them
}
