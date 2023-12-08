rule Lazarus_Dec_17_4
{
	meta:
		description = "Detects Lazarus malware from incident in Dec 2017ithumb.js"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/8U6fY2"
		date = "2017-12-20"
		hash1 = "8ff100ca86cb62117f1290e71d5f9c0519661d6c955d9fcfb71f0bbdf75b51b3"
		hash2 = "7975c09dd436fededd38acee9769ad367bfe07c769770bd152f33a10ed36529e"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "var _0xf5ed=[\"\\x57\\x53\\x63\\x72\\x69\\x70\\x74\\x2E\\x53\\x68\\x65\\x6C\\x6C\"," ascii

	condition:
		filesize <9KB and 1 of them
}
