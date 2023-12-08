rule visbot
{
	meta:
		description = "Detects the presence of Visbot and Pong in a file"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "stripos($buf, 'Visbot')!==false && stripos($buf, 'Pong')!==false"
		$ = "stripos($buf, 'Visbot') !== false && stripos($buf, 'Pong')"

	condition:
		any of them
}
