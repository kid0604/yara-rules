rule Ransom_TeslaCrypt
{
	meta:
		description = "Detect the risk of Ransomware TeslaCrypt Rule 1"
		hash1 = "3372c1edab46837f1e973164fa2d726c5c5e17bcb888828ccd7c4dfcc234a370"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s\\system32\\cmd.exe" fullword wide
		$s2 = "mshta.exe \"http://50.7.138.132/?Subject=ping&addr=%s&&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d\"" fullword ascii
		$s3 = " !!!-key = %s -!!!" fullword ascii
		$s4 = " /c start \"\" \"%s\"" fullword wide
		$s5 = "1. Download Tor Browser from http://torproject.org" fullword ascii
		$s6 = "7tno4hib47vlep5o.tor2web.org" fullword ascii
		$s7 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)" fullword ascii
		$s8 = "with strongest encryption and unique key, generated for this computer." fullword ascii
		$s9 = "https://7tno4hib47vlep5o.tor2web.org" fullword wide
		$s10 = "in immediate elimination of the private key by the server." fullword wide
		$s11 = "if https://34r6hq26q2h4jkzj.tor2web.org is not opening, please follow the steps: " fullword wide
		$s12 = "Encryption was produced using a unique public key RSA-2048 generated " fullword wide
		$s13 = "https://34r6hq26q2h4jkzj.tor2web.org" fullword wide
		$s14 = "!!!Decrypt your files!!!" fullword wide
		$s15 = "Enter Decrypt key" fullword wide
		$s16 = "Enter Decrypt Key" fullword wide
		$s17 = "Your personal files are encrypted!" fullword wide
		$s18 = "\\HELP_TO_DECRYPT_YOUR_FILES.txt" fullword wide
		$s19 = "Subject=Ping&key=%s&addr=%s&files=%d&size=%d&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d&gate=G%d" fullword ascii
		$s20 = "Subject=Payment&recovery_key=%s&addr=%s&files=%d&size=%d&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d" fullword ascii
		$s21 = "Subject=Crypted&key=%s&addr=%s&files=%lld&size=%lld&version=%s&date=%lld&OS=%ld&ID=%d&subid=%d&gate=G%d" fullword ascii
		$s22 = "vssadmin delete shadows /all" fullword ascii
		$s23 = "procexp" fullword wide
		$s24 = "Your payment is not received !!!" fullword wide
		$s25 = "7tno4hib47vlep5o.tor2web.fi" fullword ascii
		$s26 = "Your documents, photos, databases and other important files have been encrypted" fullword ascii
		$s27 = "7tno4hib47vlep5o.tor2web.blutmagie.de" fullword ascii
		$s28 = "decrypt your files until you pay and obtain the private key." fullword ascii
		$s29 = "CBigNum::operator= : BN_copy failed" fullword ascii
		$s30 = "https://7tno4hib47vlep5o.tor2web.fi" fullword wide
		$s31 = "https://7tno4hib47vlep5o.tor2web.blutmagie.de" fullword wide
		$s32 = "ComSpec" fullword wide
		$s33 = "https://34r6hq26q2h4jkzj.tor2web.fi" fullword wide
		$s34 = "The only copy of the private key, which will allow you to decrypt your files, " fullword wide
		$s35 = "Click \"Show encrypted files\" Button to view a complete list of encrypted files," fullword wide
		$s36 = "\\CryptoLocker.lnk" fullword wide
		$s37 = "\\key.dat" fullword wide
		$s38 = "Open http://34r6hq26q2h4jkzj.tor2web.fi or http://34r6hq26q2h4jkzj.onion.cab" fullword ascii
		$s39 = "Now you have the last chance to decrypt your files." fullword ascii
		$s40 = "msconfig" fullword wide
		$s41 = "Any attempt to remove or corrupt this software will result " fullword wide
		$s42 = "All files Decrypted" fullword wide
		$s43 = "in your browser. They are public gates to the secret server." fullword ascii
		$s44 = "https://blockchain.info/address/%s" fullword ascii
		$s45 = " Type Descriptor'" fullword ascii
		$s46 = "After instalation,run the browser and enter address " fullword wide
		$s47 = "www.torproject.org/projects/torbrowser.html.en" fullword wide
		$s48 = "private key." fullword wide
		$s49 = "Your private key will be " fullword wide
		$s50 = "https://www.torproject.org/projects/torbrowser.html.en" fullword wide
		$s51 = "\\HELP_TO_DECRYPT_YOUR_FILES.bmp" fullword wide
		$s52 = "3|$(3\\$ " fullword ascii
		$s53 = "---!!!Done!!!---" fullword ascii
		$s54 = " constructor or from DllMain." fullword ascii
		$s55 = "Enter Decryption key here" fullword wide
		$s56 = "Decryption key:" fullword wide
		$s57 = "Show encrypted files" fullword wide
		$s58 = "You must install this browser" fullword wide
		$s59 = "for this computer. To decrypt files you need to obtain the " fullword wide
		$s60 = "Your files have been safely encrypted on this PC: photos,videos, documents,etc. " fullword wide
		$s61 = "Please  wait !!! " fullword wide
		$s62 = "Private decryption key is stored on a secret Internet server and nobody can" fullword ascii
		$s63 = "System1230123" fullword wide
		$s64 = "Copy and paste the following Bitcoin address in the input form on server. Avoid missprints." fullword ascii
		$s65 = ".?AVbignum_error@@" fullword ascii
		$s66 = "EncodeBase58 : BN_div failed" fullword ascii
		$s67 = "/api/v0/addresses/%s" fullword ascii
		$s68 = "CBigNum conversion from unsigned long : BN_set_word failed" fullword ascii
		$s69 = "bitcoin.toshi.io" fullword ascii
		$s70 = "2. In the Tor Browser open the http://34r6hq26q2h4jkzj.onion/ " fullword ascii
		$s71 = "/state.php?%s" fullword ascii
		$s72 = "If you have problems with gates, use direct connection:" fullword ascii
		$s73 = "file crypted %s <br>" fullword wide
		$s74 = "Check Key" fullword wide
		$s75 = "Click to copy Bitcoin address to clipboard" fullword wide
		$s76 = "34r6hq26q2h4jkzj.onion " fullword wide
		$s77 = "\\log.html" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <900KB and 5 of them
}
