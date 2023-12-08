rule md5_71a7c769e644d8cf3cf32419239212c7
{
	meta:
		description = "Detects usage of $GLOBALS['...']($GLOBALS['...'] in scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\$GLOBALS\['[\w\d]+'\]\(\$GLOBALS\['[\w\d]+'\]/

	condition:
		any of them
}
