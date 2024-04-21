rule case_18190_nokoyawa_k
{
	meta:
		description = "18190 - file k.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/"
		date = "2023-05-21"
		hash1 = "7095beafff5837070a89407c1bf3c6acf8221ed786e0697f6c578d4c3de0efd6"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "UncategorizedOtherOutOfMemoryUnexpectedEofInterruptedArgumentListTooLongInvalidFilenameTooManyLinksCrossesDevicesDeadlockExecuta" ascii
		$x2 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\legacy.rs" fullword ascii
		$x3 = "C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\v0.rs" fullword ascii
		$s4 = ".llvm.C:\\Users\\runneradmin\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rustc-demangle-0.1.21\\src\\lib.rs" fullword ascii
		$s5 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\cipher-0.4.3\\src\\stream.rs" fullword ascii
		$s6 = "called `Option::unwrap()` on a `None` valueC:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.8" ascii
		$s7 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\rand_core-0.5.1\\src\\os.rs" fullword ascii
		$s8 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\generic-array-0.14.6\\src\\lib.rs" fullword ascii
		$s9 = "C:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\base64-0.3.1\\src\\lib.rs" fullword ascii
		$s10 = "Y:\\noko\\target\\release\\deps\\noko.pdb" fullword ascii
		$s11 = " --config <base64 encoded config> --file <filePath> (encrypt selected file)" fullword ascii
		$s12 = " --config <base64 encoded config> --dir <dirPath> (encrypt selected directory)" fullword ascii
		$s13 = "uncategorized errorother errorout of memoryunexpected end of fileunsupportedoperation interruptedargument list too longinvalid f" ascii
		$s14 = "called `Option::unwrap()` on a `None` valueC:\\Users\\user\\.cargo\\registry\\src\\github.com-1ecc6299db9ec823\\serde_json-1.0.8" ascii
		$s15 = "    --config <base64 encoded config> (to start full encryption)" fullword ascii
		$s16 = "assertion failed: state_and_queue.addr() & STATE_MASK == RUNNINGOnce instance has previously been poisoned" fullword ascii
		$s17 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s18 = "toryoperation would blockentity already existsbroken pipenetwork downaddress not availableaddress in usenot connectedconnection " ascii
		$s19 = "randSecure: random number generator module is not initializedstdweb: failed to get randomnessstdweb: no randomness source availa" ascii
		$s20 = "lock count overflow in reentrant mutexlibrary\\std\\src\\sys_common\\remutex.rs" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 1 of ($x*) and 4 of them
}
