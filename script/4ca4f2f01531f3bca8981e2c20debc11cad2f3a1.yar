rule PUA_Crypto_Mining_CommandLine_Indicators_Oct21 : SCRIPT
{
	meta:
		description = "Detects command line parameters often used by crypto mining software"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.poolwatch.io/coin/monero"
		date = "2021-10-24"
		score = 65
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s01 = " --cpu-priority="
		$s02 = "--donate-level=0"
		$s03 = " -o pool."
		$s04 = " -o stratum+tcp://"
		$s05 = " --nicehash"
		$s06 = " --algo=rx/0 "
		$se1 = "LS1kb25hdGUtbGV2ZWw9"
		$se2 = "0tZG9uYXRlLWxldmVsP"
		$se3 = "tLWRvbmF0ZS1sZXZlbD"
		$se4 = "c3RyYXR1bSt0Y3A6Ly"
		$se5 = "N0cmF0dW0rdGNwOi8v"
		$se6 = "zdHJhdHVtK3RjcDovL"
		$se7 = "c3RyYXR1bSt1ZHA6Ly"
		$se8 = "N0cmF0dW0rdWRwOi8v"
		$se9 = "zdHJhdHVtK3VkcDovL"

	condition:
		filesize <5000KB and 1 of them
}
