import "pe"

rule SUSP_ScreenConnect_User_PoC_Com_Unused_Feb24
{
	meta:
		description = "Detects suspicious ScreenConnect user with poc.com email address, which is a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability with the POC released by WatchTower and the account wasn't actually used yet to login"
		author = "Florian Roth"
		reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
		date = "2024-02-23"
		score = 65
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "<Users xmlns:xsi="
		$a2 = "<CreationDate>"
		$s1 = "@poc.com</Email>"
		$s2 = "<LastLoginDate>0001"

	condition:
		filesize <200KB and all of ($a*) and all of ($s*)
}
