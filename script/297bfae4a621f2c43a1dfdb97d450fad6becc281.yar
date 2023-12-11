rule blackhole_basic : EK
{
	meta:
		description = "Detects blackhole exploit kit patterns in web traffic"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a = /\.php\?.*?\:[a-zA-Z0-9\:]{6,}?\&.*?\&/

	condition:
		$a
}
