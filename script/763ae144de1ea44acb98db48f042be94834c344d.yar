rule tick_app_js
{
	meta:
		description = "JavaScript malware downloaded using a vulnerability in SKYSEA"
		author = "JPCERT/CC Incident Response Group"
		hash = "f36db81d384e3c821b496c8faf35a61446635f38a57d04bde0b3dfd19b674587"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sa = "File download error!"
		$sb = "/tools/uninstaller.sh"
		$sc = "./npm stop"

	condition:
		all of them
}
